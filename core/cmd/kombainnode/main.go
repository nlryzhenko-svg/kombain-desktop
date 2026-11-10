// kombain-node: runs kombain-node.sh on a server over SSH for the Kombain desktop app.
//
// Input (stdin, JSON): {"host","port","user","password","key","hostKey","args":[...]}
// Output (stdout): the script's own lines (KB_STEP / KB_ERROR / KB_RESULT / KB_STATS ...)
// plus "KB_HOSTKEY <fingerprint>" after connecting and "KB_LOG <text>" for local progress.
// Exit code: 0 ok, 1 error (an explanatory KB_ERROR line is printed).
package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

//go:embed kombain-node.sh
var script []byte

type request struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	User     string   `json:"user"`
	Password string   `json:"password"`
	Key      string   `json:"key"`
	HostKey  string   `json:"hostKey"`
	Args     []string `json:"args"`
}

func out(format string, a ...any) { fmt.Printf(format+"\n", a...) }

func fail(msg string) {
	out("KB_ERROR %s", msg)
	os.Exit(1)
}

func quote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func main() {
	var req request
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fail("неверный запрос: " + err.Error())
	}
	if req.Port == 0 {
		req.Port = 22
	}
	if req.User == "" {
		req.User = "root"
	}

	var auths []ssh.AuthMethod
	if strings.TrimSpace(req.Key) != "" {
		var signer ssh.Signer
		var err error
		if req.Password != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(strings.TrimSpace(req.Key)), []byte(req.Password))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(strings.TrimSpace(req.Key)))
		}
		if err != nil {
			fail("не удалось прочитать ключ SSH: " + err.Error())
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if req.Password != "" && strings.TrimSpace(req.Key) == "" {
		pw := req.Password
		auths = append(auths, ssh.Password(pw), ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}))
	}
	if len(auths) == 0 {
		fail("укажите пароль или ключ SSH")
	}

	var seen string
	cfg := &ssh.ClientConfig{
		User: req.User,
		Auth: auths,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = ssh.FingerprintSHA256(key)
			if req.HostKey != "" && req.HostKey != seen {
				return errors.New("hostkey")
			}
			return nil
		},
		Timeout: 15 * time.Second,
	}
	addr := net.JoinHostPort(strings.TrimSpace(req.Host), strconv.Itoa(req.Port))
	out("KB_LOG Подключаюсь к %s…", addr)
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		m := err.Error()
		switch {
		case strings.Contains(m, "hostkey"):
			fail(fmt.Sprintf("Ключ сервера изменился (%s). Если вы переустанавливали сервер — удалите его из списка и добавьте заново.", seen))
		case strings.Contains(m, "unable to authenticate"):
			fail("Неверный логин, пароль или ключ")
		case strings.Contains(m, "timeout"), strings.Contains(m, "i/o timeout"):
			fail("Сервер не отвечает (проверьте IP и SSH-порт)")
		case strings.Contains(m, "refused"):
			fail("Порт SSH закрыт (проверьте SSH-порт)")
		default:
			fail("Не удалось подключиться: " + m)
		}
	}
	defer client.Close()
	out("KB_HOSTKEY %s", seen)

	run := func(cmd string, stdin []byte, onLine func(string)) (int, error) {
		sess, err := client.NewSession()
		if err != nil {
			return -1, err
		}
		defer sess.Close()
		if stdin != nil {
			sess.Stdin = strings.NewReader(string(stdin))
		}
		pr, pw := io.Pipe()
		sess.Stdout = pw
		sess.Stderr = pw
		done := make(chan struct{})
		go func() {
			sc := bufio.NewScanner(pr)
			sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
			for sc.Scan() {
				onLine(sc.Text())
			}
			close(done)
		}()
		err = sess.Run(cmd)
		pw.Close()
		<-done
		if err != nil {
			var ee *ssh.ExitError
			if errors.As(err, &ee) {
				return ee.ExitStatus(), nil
			}
			return -1, err
		}
		return 0, nil
	}

	path := "/tmp/kombain-node.sh"
	if _, err := run("cat > "+path+" && chmod 700 "+path, script, func(string) {}); err != nil {
		fail("не удалось загрузить скрипт: " + err.Error())
	}
	parts := make([]string, len(req.Args))
	for i, a := range req.Args {
		parts[i] = quote(a)
	}
	args := strings.Join(parts, " ")
	root := req.User == "root"
	var cmd string
	var stdin []byte
	switch {
	case root:
		cmd = "bash " + path + " " + args + " 2>&1"
	case req.Password != "":
		cmd = "sudo -S -p '' bash " + path + " " + args + " 2>&1"
		stdin = []byte(req.Password + "\n")
	default:
		cmd = "sudo -n bash " + path + " " + args + " 2>&1"
	}
	sawError := false
	code, err := run(cmd, stdin, func(line string) {
		if strings.HasPrefix(line, "KB_ERROR ") {
			sawError = true
		}
		fmt.Println(line)
	})
	_, _ = run("rm -f "+path, nil, func(string) {})
	if err != nil {
		fail("Ошибка SSH: " + err.Error())
	}
	if code != 0 {
		if !sawError {
			if !root {
				fail(fmt.Sprintf("Команда завершилась с кодом %d (нужен sudo без ограничений или вход под root)", code))
			}
			fail(fmt.Sprintf("Команда завершилась с кодом %d", code))
		}
		os.Exit(1)
	}
}
