// Kombain «Мои серверы» for the desktop app. The server side is the same kombain-node.sh the phone uses;
// SSH is done by the bundled kombain-node helper (Go), so this file only drives it and shows the results.
#include "include/ui/kombain/kombain_servers.h"

#include "3rdparty/qrcodegen.hpp"
#include "include/configs/sub/GroupUpdater.hpp"
#include "include/database/DatabaseManager.h"
#include "include/database/GroupsRepo.h"
#include "include/database/SettingsRepo.h"
#include "include/engine/services/GroupService.h"
#include "include/global/Utils.hpp"

#include <QApplication>
#include <QButtonGroup>
#include <QCheckBox>
#include <QClipboard>
#include <QCoreApplication>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QDir>
#include <QFile>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollArea>
#include <QSpinBox>
#include <QTabWidget>
#include <QTimer>
#include <QToolButton>
#include <QUuid>
#include <QVBoxLayout>

#ifdef Q_OS_WIN
#include <windows.h>
#include <dpapi.h>
#pragma comment(lib, "crypt32.lib")
#endif

namespace Kombain {

    // ------------------------------------------------------------------ secrets

    static QString protect(const QString &plain) {
        if (plain.isEmpty()) return {};
        QByteArray in = plain.toUtf8();
#ifdef Q_OS_WIN
        DATA_BLOB src{static_cast<DWORD>(in.size()), reinterpret_cast<BYTE *>(in.data())};
        DATA_BLOB out{};
        if (CryptProtectData(&src, L"Kombain", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
            QByteArray enc(reinterpret_cast<const char *>(out.pbData), static_cast<int>(out.cbData));
            LocalFree(out.pbData);
            return "dpapi:" + QString::fromLatin1(enc.toBase64());
        }
#endif
        return "b64:" + QString::fromLatin1(in.toBase64());
    }

    static QString unprotect(const QString &stored) {
        if (stored.startsWith("b64:")) return QString::fromUtf8(QByteArray::fromBase64(stored.mid(4).toLatin1()));
#ifdef Q_OS_WIN
        if (stored.startsWith("dpapi:")) {
            QByteArray enc = QByteArray::fromBase64(stored.mid(6).toLatin1());
            DATA_BLOB src{static_cast<DWORD>(enc.size()), reinterpret_cast<BYTE *>(enc.data())};
            DATA_BLOB out{};
            if (CryptUnprotectData(&src, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
                QString s = QString::fromUtf8(reinterpret_cast<const char *>(out.pbData), static_cast<int>(out.cbData));
                LocalFree(out.pbData);
                return s;
            }
        }
#endif
        return stored;
    }

    // ------------------------------------------------------------------ model

    QJsonObject ServerNode::toJson() const {
        QJsonObject o;
        o["id"] = id; o["name"] = name; o["host"] = host; o["user"] = user;
        o["password"] = protect(password); o["key"] = protect(key);
        o["sni"] = sni; o["hostKey"] = hostKey; o["sshPort"] = sshPort; o["role"] = role; o["exitId"] = exitId;
        o["protocols"] = protocols; o["vpnPort"] = vpnPort; o["xhPort"] = xhPort; o["hyPort"] = hyPort;
        o["tuicPort"] = tuicPort; o["groupId"] = groupId; o["stats"] = stats; o["statsAt"] = statsAt;
        o["health"] = health;
        return o;
    }

    ServerNode ServerNode::fromJson(const QJsonObject &o) {
        ServerNode n;
        n.id = o["id"].toString(); n.name = o["name"].toString(); n.host = o["host"].toString();
        n.user = o["user"].toString("root"); n.password = unprotect(o["password"].toString());
        n.key = unprotect(o["key"].toString()); n.sni = o["sni"].toString(); n.hostKey = o["hostKey"].toString();
        n.sshPort = o["sshPort"].toInt(22); n.role = o["role"].toString("single"); n.exitId = o["exitId"].toString();
        n.protocols = o["protocols"].toString("vless,hy2"); n.vpnPort = o["vpnPort"].toInt(443);
        n.xhPort = o["xhPort"].toInt(8443); n.hyPort = o["hyPort"].toInt(443); n.tuicPort = o["tuicPort"].toInt(8443);
        n.groupId = o["groupId"].toInt(-1); n.stats = o["stats"].toString();
        n.statsAt = o["statsAt"].toVariant().toLongLong(); n.health = o["health"].toString();
        return n;
    }

    static QString storePath() { return QDir::current().absoluteFilePath("kombain_servers.json"); }

    QList<ServerNode> ServerStore::all() {
        QFile f(storePath());
        QList<ServerNode> list;
        if (!f.open(QIODevice::ReadOnly)) return list;
        for (const auto &v: QJsonDocument::fromJson(f.readAll()).array()) list << ServerNode::fromJson(v.toObject());
        return list;
    }

    void ServerStore::saveAll(const QList<ServerNode> &list) {
        QJsonArray arr;
        for (const auto &n: list) arr << n.toJson();
        QFile f(storePath());
        if (f.open(QIODevice::WriteOnly | QIODevice::Truncate)) f.write(QJsonDocument(arr).toJson());
    }

    void ServerStore::upsert(const ServerNode &n) {
        auto list = all();
        bool found = false;
        for (auto &x: list) if (x.id == n.id) { x = n; found = true; }
        if (!found) list << n;
        saveAll(list);
    }

    void ServerStore::remove(const QString &id) {
        auto list = all();
        list.erase(std::remove_if(list.begin(), list.end(), [&](const ServerNode &n) { return n.id == id; }), list.end());
        saveAll(list);
    }

    ServerNode ServerStore::get(const QString &id, bool *ok) {
        for (const auto &n: all()) if (n.id == id) { if (ok) *ok = true; return n; }
        if (ok) *ok = false;
        return {};
    }

    QString InstallArgsProtocolsLabel(const QString &protocols) {
        QStringList out;
        for (const auto &p: protocols.split(',', Qt::SkipEmptyParts)) {
            if (p == "vless") out << "VLESS";
            else if (p == "xhttp") out << "XHTTP";
            else if (p == "hy2") out << "Hysteria2";
            else if (p == "tuic") out << "TUIC";
            else out << p;
        }
        return out.join(" + ");
    }

    static QString protoTitle(const QString &p) {
        if (p == "vless") return "VLESS Reality";
        if (p == "xhttp") return "XHTTP";
        if (p == "hy2") return "Hysteria2";
        if (p == "tuic") return "TUIC";
        return p;
    }

    static QString humanSize(qint64 b) {
        const char *u[] = {"Б", "КБ", "МБ", "ГБ", "ТБ"};
        double v = static_cast<double>(b);
        int i = 0;
        while (v >= 1024 && i < 4) { v /= 1024; i++; }
        return QString::number(v, 'f', i == 0 ? 0 : 1) + " " + QString::fromUtf8(u[i]);
    }

    static QString uptimeText(qint64 s) {
        if (s >= 86400) return QString("%1 дн %2 ч").arg(s / 86400).arg(s % 86400 / 3600);
        if (s >= 3600) return QString("%1 ч %2 мин").arg(s / 3600).arg(s % 3600 / 60);
        return QString("%1 мин").arg(s / 60);
    }

    static QString healthProblem(const QJsonObject &st) {
        QStringList down;
        for (const auto &v: st["services"].toArray()) {
            const auto o = v.toObject();
            const auto state = o["state"].toString();
            if (state != "active" && state != "unknown") down << o["name"].toString();
        }
        if (!down.isEmpty()) return "Не работает: " + down.join(", ");
        if (st["diskPct"].toInt() >= 95) return QString("Диск заполнен на %1%").arg(st["diskPct"].toInt());
        return {};
    }

    static QString healthSummary(const QJsonObject &st) {
        const qint64 total = st["memTotalKb"].toVariant().toLongLong(), avail = st["memAvailKb"].toVariant().toLongLong();
        const int mem = total > 0 ? static_cast<int>((total - avail) * 100 / total) : 0;
        return QString("Нагрузка %1 · ОЗУ %2% · работает %3\nТрафик сервера: ↓ %4 ↑ %5")
            .arg(st["load"].toString().section(' ', 0, 0)).arg(mem)
            .arg(uptimeText(st["uptime"].toVariant().toLongLong()))
            .arg(humanSize(st["rx"].toVariant().toLongLong()), humanSize(st["tx"].toVariant().toLongLong()));
    }

    // ------------------------------------------------------------------ NodeRun

    static QString helperPath() {
        QDir dir(QCoreApplication::applicationDirPath());
#ifdef Q_OS_WIN
        return dir.absoluteFilePath("kombain-node.exe");
#else
        return dir.absoluteFilePath("kombain-node");
#endif
    }

    NodeRun::NodeRun(const ServerNode &n, const QStringList &a, QObject *parent) : QObject(parent), node(n), args(a) {
        proc.setProcessChannelMode(QProcess::MergedChannels);
        connect(&proc, &QProcess::readyReadStandardOutput, this, [this] {
            buffer += proc.readAllStandardOutput();
            int nl;
            while ((nl = buffer.indexOf('\n')) >= 0) {
                handleLine(QString::fromUtf8(buffer.left(nl)).trimmed());
                buffer.remove(0, nl + 1);
            }
        });
        connect(&proc, &QProcess::finished, this, [this](int code, QProcess::ExitStatus) {
            if (!buffer.isEmpty()) handleLine(QString::fromUtf8(buffer).trimmed());
            buffer.clear();
            if (code != 0 && error.isEmpty()) error = QString("Помощник завершился с кодом %1").arg(code);
            const bool ok = error.isEmpty() && (!result.isEmpty() || !stats.isEmpty() || args.value(0) == "status" || args.value(0) == "uninstall");
            emit finished(ok);
        });
        connect(&proc, &QProcess::errorOccurred, this, [this](QProcess::ProcessError e) {
            if (e == QProcess::FailedToStart) {
                error = "Не найден kombain-node — переустановите Kombain";
                emit finished(false);
            }
        });
    }

    void NodeRun::handleLine(const QString &l) {
        if (l.isEmpty()) return;
        if (l.startsWith("KB_STEP ")) emit line("• " + l.mid(8));
        else if (l.startsWith("KB_LOG ")) emit line(l.mid(7));
        else if (l.startsWith("KB_ERROR ")) { error = l.mid(9); emit line("✖ " + error); }
        else if (l.startsWith("KB_HOSTKEY ")) {
            const auto fp = l.mid(11);
            if (node.hostKey.isEmpty()) { node.hostKey = fp; emit line("Отпечаток сервера: " + fp); }
        } else if (l.startsWith("KB_RESULT ")) result = QJsonDocument::fromJson(QByteArray::fromBase64(l.mid(10).toLatin1())).object();
        else if (l.startsWith("KB_STATS ")) stats = QJsonDocument::fromJson(QByteArray::fromBase64(l.mid(9).toLatin1())).object();
        else emit line("  " + l);
    }

    void NodeRun::start() {
        QJsonObject req;
        req["host"] = node.host.trimmed(); req["port"] = node.sshPort; req["user"] = node.user;
        req["password"] = node.password; req["key"] = node.key; req["hostKey"] = node.hostKey;
        QJsonArray a;
        for (const auto &x: args) a << x;
        req["args"] = a;
        proc.start(helperPath(), {});
        if (!proc.waitForStarted(5000)) return;
        proc.write(QJsonDocument(req).toJson(QJsonDocument::Compact));
        proc.write("\n");
        proc.closeWriteChannel();
    }

    // ------------------------------------------------------------------ QR / links

    static QPixmap qrPixmap(const QString &text, int side) {
        try {
            const auto qr = qrcodegen::QrCode::encodeText(text.toUtf8().constData(), qrcodegen::QrCode::Ecc::MEDIUM);
            const int sz = qr.getSize(), pad = 2;
            QImage im(sz + pad * 2, sz + pad * 2, QImage::Format_RGB32);
            im.fill(Qt::white);
            for (int y = 0; y < sz; y++)
                for (int x = 0; x < sz; x++)
                    if (qr.getModule(x, y)) im.setPixel(x + pad, y + pad, qRgb(0, 0, 0));
            return QPixmap::fromImage(im.scaled(side, side, Qt::KeepAspectRatio, Qt::FastTransformation));
        } catch (...) {
            return {};
        }
    }

    void ShowUserLinks(QWidget *parent, const QString &title, const QList<QPair<QString, QString>> &protoLinks) {
        QDialog dlg(parent);
        dlg.setWindowTitle(title);
        auto *lay = new QVBoxLayout(&dlg);
        auto *hint = new QLabel("Отсканируйте QR-код в Kombain на телефоне, Happ, v2rayNG или Hiddify.\nКаждая вкладка — отдельный протокол.");
        hint->setProperty("kombainMuted", true);
        lay->addWidget(hint);
        auto *tabs = new QTabWidget;
        QStringList all;
        for (const auto &[proto, link]: protoLinks) {
            auto *page = new QWidget;
            auto *pl = new QVBoxLayout(page);
            auto *img = new QLabel;
            img->setAlignment(Qt::AlignCenter);
            img->setPixmap(qrPixmap(link, 320));
            pl->addWidget(img);
            auto *text = new QPlainTextEdit(link);
            text->setReadOnly(true);
            text->setMaximumHeight(70);
            pl->addWidget(text);
            tabs->addTab(page, protoTitle(proto));
            all << link;
        }
        lay->addWidget(tabs);
        auto *row = new QHBoxLayout;
        auto *copy = new QPushButton("Копировать все ссылки");
        QObject::connect(copy, &QPushButton::clicked, &dlg, [all, copy] {
            QGuiApplication::clipboard()->setText(all.join("\n"));
            copy->setText("Скопировано ✓");
        });
        auto *close = new QPushButton("Готово");
        close->setDefault(true);
        QObject::connect(close, &QPushButton::clicked, &dlg, &QDialog::accept);
        row->addWidget(copy);
        row->addStretch();
        row->addWidget(close);
        lay->addLayout(row);
        dlg.resize(460, 600);
        dlg.exec();
    }

    // ------------------------------------------------------------------ wizard

    class ServerWizard : public QDialog {
    public:
        struct Form {
            QWidget *box;
            QLineEdit *name, *host, *user, *pass, *sni;
            QSpinBox *port;
            QPlainTextEdit *key;
            QLabel *title, *hint;
        };
        Form mainForm{}, entryForm{};
        QRadioButton *single, *cascade;
        QCheckBox *pVless, *pXhttp, *pHy2, *pTuic;
        QSpinBox *portVless, *portXhttp, *portHy, *portTuic;
        QLabel *modeHint;

        static QSpinBox *portBox(int v) {
            auto *s = new QSpinBox;
            s->setRange(1, 65535);
            s->setValue(v);
            return s;
        }

        Form makeForm(const QString &defaultSni) {
            Form f{};
            f.box = new QFrame;
            f.box->setProperty("kombainCard", true);
            auto *l = new QVBoxLayout(f.box);
            f.title = new QLabel;
            f.title->setStyleSheet("font-size: 15px; font-weight: 600;");
            f.hint = new QLabel;
            f.hint->setProperty("kombainMuted", true);
            f.hint->setWordWrap(true);
            l->addWidget(f.title);
            l->addWidget(f.hint);
            auto *grid = new QFormLayout;
            f.name = new QLineEdit;
            f.name->setPlaceholderText("Например: Нидерланды");
            f.host = new QLineEdit;
            f.host->setPlaceholderText("IP или домен VPS");
            f.port = portBox(22);
            f.user = new QLineEdit("root");
            f.pass = new QLineEdit;
            f.pass->setEchoMode(QLineEdit::Password);
            f.key = new QPlainTextEdit;
            f.key->setPlaceholderText("Ключ SSH (если входите по ключу) — вставьте содержимое id_ed25519 / id_rsa");
            f.key->setMaximumHeight(60);
            f.sni = new QLineEdit(defaultSni);
            grid->addRow("Название", f.name);
            auto *hostRow = new QHBoxLayout;
            hostRow->addWidget(f.host, 1);
            hostRow->addWidget(new QLabel("SSH-порт"));
            hostRow->addWidget(f.port);
            grid->addRow("Адрес", hostRow);
            auto *authRow = new QHBoxLayout;
            authRow->addWidget(f.user);
            authRow->addWidget(new QLabel("Пароль"));
            authRow->addWidget(f.pass, 1);
            grid->addRow("Логин", authRow);
            grid->addRow("Ключ", f.key);
            grid->addRow("Сайт для маскировки", f.sni);
            l->addLayout(grid);
            return f;
        }

        explicit ServerWizard(QWidget *parent) : QDialog(parent) {
            setWindowTitle("Поднять сервер");
            auto *outer = new QVBoxLayout(this);
            auto *scroll = new QScrollArea;
            scroll->setWidgetResizable(true);
            scroll->setFrameShape(QFrame::NoFrame);
            auto *content = new QWidget;
            auto *lay = new QVBoxLayout(content);
            auto *modeRow = new QHBoxLayout;
            single = new QRadioButton("Одна нода");
            cascade = new QRadioButton("Каскад (РФ → зарубеж)");
            single->setChecked(true);
            modeRow->addWidget(single);
            modeRow->addWidget(cascade);
            modeRow->addStretch();
            lay->addLayout(modeRow);
            modeHint = new QLabel;
            modeHint->setWordWrap(true);
            modeHint->setProperty("kombainMuted", true);
            lay->addWidget(modeHint);
            entryForm = makeForm("ya.ru");
            mainForm = makeForm("www.microsoft.com");
            lay->addWidget(entryForm.box);
            lay->addWidget(mainForm.box);

            auto *protoBox = new QFrame;
            protoBox->setProperty("kombainCard", true);
            auto *pl = new QVBoxLayout(protoBox);
            auto *pt = new QLabel("Протоколы");
            pt->setStyleSheet("font-size: 15px; font-weight: 600;");
            pl->addWidget(pt);
            pVless = new QCheckBox("VLESS + Reality — основной, маскируется под обычный сайт");
            pXhttp = new QCheckBox("VLESS + XHTTP + Reality — держится, когда режут обычный Reality");
            pHy2 = new QCheckBox("Hysteria2 — быстрый на плохих сетях (UDP)");
            pTuic = new QCheckBox("TUIC v5 — запасной вариант на QUIC (UDP)");
            pVless->setChecked(true); pXhttp->setChecked(true); pHy2->setChecked(true);
            for (auto *c: {pVless, pXhttp, pHy2, pTuic}) pl->addWidget(c);
            auto *ports = new QGridLayout;
            portVless = portBox(443); portXhttp = portBox(8443); portHy = portBox(443); portTuic = portBox(8443);
            ports->addWidget(new QLabel("Порт VLESS (TCP)"), 0, 0); ports->addWidget(portVless, 0, 1);
            ports->addWidget(new QLabel("Порт Hysteria2 (UDP)"), 0, 2); ports->addWidget(portHy, 0, 3);
            ports->addWidget(new QLabel("Порт XHTTP (TCP)"), 1, 0); ports->addWidget(portXhttp, 1, 1);
            ports->addWidget(new QLabel("Порт TUIC (UDP)"), 1, 2); ports->addWidget(portTuic, 1, 3);
            pl->addLayout(ports);
            lay->addWidget(protoBox);

            auto *note = new QLabel("Kombain зайдёт на сервер по SSH, скачает Xray, Hysteria2 и (для TUIC) sing-box с GitHub, "
                                    "создаст ключи, откроет порты и запустит службы. Нужен VPS с Debian или Ubuntu. "
                                    "Пароль хранится на компьютере в зашифрованном виде.");
            note->setWordWrap(true);
            note->setProperty("kombainMuted", true);
            lay->addWidget(note);
            lay->addStretch();
            scroll->setWidget(content);
            outer->addWidget(scroll);

            auto *buttons = new QDialogButtonBox;
            auto *install = buttons->addButton("Установить", QDialogButtonBox::AcceptRole);
            install->setDefault(true);
            buttons->addButton("Отмена", QDialogButtonBox::RejectRole);
            connect(buttons, &QDialogButtonBox::accepted, this, &ServerWizard::tryAccept);
            connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
            outer->addWidget(buttons);
            connect(single, &QRadioButton::toggled, this, [this] { applyMode(); });
            applyMode();
            resize(640, 780);
        }

        void applyMode() {
            const bool c = cascade->isChecked();
            modeHint->setText(c ? "Каскад: телефон или компьютер подключается к входному серверу в России (лучше с «белым» IP), "
                                  "тот передаёт трафик на выходной за рубежом. Российские сайты идут с входного напрямую."
                                : "Один сервер за рубежом: вы подключаетесь к нему и выходите в интернет оттуда.");
            entryForm.box->setVisible(c);
            entryForm.title->setText("Входной сервер (в России)");
            entryForm.hint->setText("К нему подключаются устройства. Маскировка — под российский сайт.");
            mainForm.title->setText(c ? "Выходной сервер (за рубежом)" : "Сервер");
            mainForm.hint->setText(c ? "Через него трафик выходит в интернет." : "VPS за рубежом.");
        }

        QString protocols() const {
            QStringList p;
            if (pVless->isChecked()) p << "vless";
            if (pXhttp->isChecked()) p << "xhttp";
            if (pHy2->isChecked()) p << "hy2";
            if (pTuic->isChecked()) p << "tuic";
            return p.join(",");
        }

        bool readNode(const Form &f, const QString &defName, ServerNode &n) {
            n.id = QUuid::createUuid().toString(QUuid::WithoutBraces);
            n.host = f.host->text().trimmed();
            n.sshPort = f.port->value();
            n.user = f.user->text().trimmed().isEmpty() ? "root" : f.user->text().trimmed();
            n.password = f.pass->text();
            n.key = f.key->toPlainText().trimmed();
            n.sni = f.sni->text().trimmed().remove("https://").remove('/');
            n.name = f.name->text().trimmed().isEmpty() ? defName : f.name->text().trimmed().remove('|');
            if (n.host.isEmpty()) { QMessageBox::warning(this, "Kombain", "Укажите IP-адрес сервера"); f.host->setFocus(); return false; }
            if (n.password.isEmpty() && n.key.isEmpty()) { QMessageBox::warning(this, "Kombain", "Укажите пароль или ключ SSH"); f.pass->setFocus(); return false; }
            if (n.sni.isEmpty()) { QMessageBox::warning(this, "Kombain", "Укажите сайт для маскировки"); return false; }
            n.protocols = protocols();
            n.vpnPort = portVless->value(); n.xhPort = portXhttp->value(); n.hyPort = portHy->value(); n.tuicPort = portTuic->value();
            return true;
        }

        ServerNode mainNode, entryNode;

        void tryAccept() {
            if (protocols().isEmpty()) { QMessageBox::warning(this, "Kombain", "Выберите хотя бы один протокол"); return; }
            if ((pXhttp->isChecked() && portXhttp->value() == portVless->value()) ||
                (pTuic->isChecked() && pHy2->isChecked() && portTuic->value() == portHy->value())) {
                QMessageBox::warning(this, "Kombain", "Порты одного типа (TCP или UDP) должны различаться");
                return;
            }
            if (!readNode(mainForm, cascade->isChecked() ? "Выход" : "Мой сервер", mainNode)) return;
            if (cascade->isChecked()) {
                if (!readNode(entryForm, "Вход", entryNode)) return;
                // the bridge between nodes always uses VLESS Reality
                if (!mainNode.protocols.contains("vless")) mainNode.protocols = "vless," + mainNode.protocols;
            }
            accept();
        }
    };

    // ------------------------------------------------------------------ dialog

    static QStringList installArgs(const ServerNode &n, const QStringList &extra = {}) {
        return QStringList{"install", "--host", n.host.trimmed(), "--protocols", n.protocols, "--sni", n.sni,
                           "--port", QString::number(n.vpnPort), "--hy-port", QString::number(n.hyPort),
                           "--xh-port", QString::number(n.xhPort), "--tuic-port", QString::number(n.tuicPort),
                           "--name", n.name} + extra;
    }

    MyServersDialog::MyServersDialog(QWidget *parent) : QDialog(parent) {
        setWindowTitle("Мои серверы");
        auto *outer = new QVBoxLayout(this);
        auto *scroll = new QScrollArea;
        scroll->setWidgetResizable(true);
        scroll->setFrameShape(QFrame::NoFrame);
        auto *content = new QWidget;
        auto *lay = new QVBoxLayout(content);

        auto *hero = new QFrame;
        hero->setProperty("kombainHero", true);
        auto *hl = new QVBoxLayout(hero);
        hl->setContentsMargins(20, 18, 20, 18);
        auto *ht = new QLabel("Свой VPN-сервер");
        ht->setStyleSheet("font-size: 20px; font-weight: 700;");
        auto *hs = new QLabel("Нужен только VPS с Debian или Ubuntu и доступ по SSH. Kombain сам поставит VLESS Reality, XHTTP, "
                              "Hysteria2 и TUIC, настроит и добавит профили. Свой домен не нужен.");
        hs->setWordWrap(true);
        auto *newBtn = new QPushButton("Поднять сервер");
        newBtn->setStyleSheet("QPushButton { background: #F1FFF9; color: #0E8F69; border: none; border-radius: 12px; padding: 10px; font-weight: 700; }");
        hl->addWidget(ht);
        hl->addWidget(hs);
        hl->addWidget(newBtn);
        lay->addWidget(hero);

        logCard = new QFrame;
        logCard->setProperty("kombainCard", true);
        auto *ll = new QVBoxLayout(logCard);
        auto *logHead = new QHBoxLayout;
        logTitle = new QLabel;
        logTitle->setStyleSheet("font-size: 15px; font-weight: 600;");
        auto *copyLog = new QToolButton;
        copyLog->setText("Копировать");
        logHead->addWidget(logTitle, 1);
        logHead->addWidget(copyLog);
        ll->addLayout(logHead);
        logProgress = new QProgressBar;
        logProgress->setRange(0, 0);
        logProgress->setTextVisible(false);
        logProgress->setMaximumHeight(6);
        ll->addWidget(logProgress);
        logView = new QPlainTextEdit;
        logView->setReadOnly(true);
        logView->setMinimumHeight(170);
        QFont mono("Consolas");
        mono.setStyleHint(QFont::Monospace);
        logView->setFont(mono);
        ll->addWidget(logView);
        logCard->hide();
        lay->addWidget(logCard);

        auto *listTitle = new QLabel("Ваши серверы");
        listTitle->setProperty("kombainAccent", true);
        lay->addWidget(listTitle);
        auto *listBox = new QWidget;
        listLayout = new QVBoxLayout(listBox);
        listLayout->setContentsMargins(0, 0, 0, 0);
        lay->addWidget(listBox);
        lay->addStretch();
        scroll->setWidget(content);
        outer->addWidget(scroll);

        connect(newBtn, &QPushButton::clicked, this, [this] {
            if (running) { QMessageBox::information(this, "Kombain", "Дождитесь окончания текущей операции"); return; }
            ServerWizard w(this);
            if (w.exec() != QDialog::Accepted) return;
            if (w.cascade->isChecked()) installCascade(w.mainNode, w.entryNode);
            else installSingle(w.mainNode);
        });
        connect(copyLog, &QToolButton::clicked, this, [this] { QGuiApplication::clipboard()->setText(logView->toPlainText()); });
        reloadList();
        resize(720, 760);
    }

    void MyServersDialog::logLine(const QString &text) {
        logCard->show();
        logView->appendPlainText(text);
    }

    void MyServersDialog::beginTask(const QString &title) {
        running = true;
        logView->clear();
        logTitle->setText("Выполняется…");
        logProgress->show();
        logLine(title);
    }

    void MyServersDialog::endTask(bool ok, const QString &message) {
        running = false;
        logTitle->setText(ok ? "Готово" : "Ошибка");
        logProgress->hide();
        logLine((ok ? "✔ " : "✖ ") + message);
        reloadList();
    }

    void MyServersDialog::runOn(const ServerNode &node, const QStringList &args, const std::function<void(NodeRun *, bool)> &done) {
        auto *run = new NodeRun(node, args, this);
        connect(run, &NodeRun::line, this, &MyServersDialog::logLine);
        connect(run, &NodeRun::finished, this, [run, done](bool ok) {
            done(run, ok);
            run->deleteLater();
        });
        run->start();
    }

    void MyServersDialog::importLinks(ServerNode &node, const QString &groupName, const QJsonObject &result, bool firstUserOnly) {
        const auto links = result["links"].toArray();
        QString firstUser;
        QStringList text;
        for (const auto &v: links) {
            const auto o = v.toObject();
            if (firstUser.isEmpty()) firstUser = o["user"].toString();
            if (firstUserOnly && o["user"].toString() != firstUser) continue;
            text << o["link"].toString();
        }
        if (text.isEmpty()) return;
        // replace the previous group of this server
        if (node.groupId >= 0 && Configs::dataManager->groupsRepo->GetGroup(node.groupId)) {
            if (Engine::GroupService::Delete(node.groupId).has_value()) {
                logLine("  (старая группа используется — профили добавлены в новую)");
            }
        }
        auto group = Configs::dataManager->groupsRepo->NewGroup();
        group->name = groupName;
        Configs::dataManager->groupsRepo->AddGroup(group);
        node.groupId = group->id;
        const int gid = group->id;
        Subscription::updater()->ImportTextTo(gid, text.join("\n"), [gid](const Subscription::UpdateOutcome &) {
            // show the new server's profiles right away
            Configs::dataManager->settingsRepo->current_group = gid;
            Configs::dataManager->settingsRepo->Save();
            MW_dialog_message(MwMessage::GroupsChanged, {});
        });
        MW_dialog_message(MwMessage::GroupsChanged, {});
    }

    void MyServersDialog::installSingle(ServerNode node) {
        beginTask(QString("Установка на %1 (%2)").arg(node.name, node.host));
        node.role = "single";
        runOn(node, installArgs(node), [this](NodeRun *r, bool ok) {
            auto n = r->node;
            if (!ok) return endTask(false, r->error.isEmpty() ? "Установка не удалась" : r->error);
            importLinks(n, n.name, r->result);
            ServerStore::upsert(n);
            endTask(true, QString("Готово: профили добавлены в группу «%1».").arg(n.name));
        });
    }

    void MyServersDialog::installCascade(ServerNode exitNode, ServerNode entryNode) {
        beginTask(QString("Каскад: %1 → %2").arg(entryNode.name, exitNode.name));
        logLine("── Шаг 1 из 2: выходной сервер " + exitNode.name);
        exitNode.role = "exit";
        runOn(exitNode, installArgs(exitNode, {"--bridge"}), [this, entryNode](NodeRun *r1, bool ok1) mutable {
            const auto bridge = r1->result["bridge"].toString();
            if (!ok1 || bridge.isEmpty()) return endTask(false, r1->error.isEmpty() ? "Выходной сервер не установился" : r1->error);
            auto exitN = r1->node;
            ServerStore::upsert(exitN);
            logLine("── Шаг 2 из 2: входной сервер " + entryNode.name);
            entryNode.role = "entry";
            entryNode.exitId = exitN.id;
            runOn(entryNode, installArgs(entryNode, {"--role", "entry", "--exit-link", bridge}), [this, exitN](NodeRun *r2, bool ok2) {
                if (!ok2) return endTask(false, r2->error.isEmpty() ? "Входной сервер не установился" : r2->error);
                auto en = r2->node;
                const auto group = en.name + " → " + exitN.name;
                importLinks(en, group, r2->result);
                ServerStore::upsert(en);
                endTask(true, QString("Готово: профили в группе «%1».").arg(group));
            });
        });
    }

    void MyServersDialog::refreshProfiles(const ServerNode &s) {
        beginTask("Обновляю профили с " + s.name);
        runOn(s, {"links"}, [this](NodeRun *r, bool ok) {
            if (!ok) return endTask(false, r->error.isEmpty() ? "Не удалось получить ссылки" : r->error);
            auto n = r->node;
            QString group = n.name;
            if (n.role == "entry") {
                bool found = false;
                const auto ex = ServerStore::get(n.exitId, &found);
                if (found) group = n.name + " → " + ex.name;
            }
            importLinks(n, group, r->result);
            ServerStore::upsert(n);
            endTask(true, "Профили обновлены.");
        });
    }

    void MyServersDialog::checkServer(const ServerNode &s) {
        beginTask("Состояние " + s.name);
        runOn(s, {"stats"}, [this](NodeRun *r, bool ok) {
            auto n = r->node;
            if (!ok || r->stats.isEmpty()) {
                n.health = r->error.isEmpty() ? "не отвечает" : r->error;
                ServerStore::upsert(n);
                return endTask(false, n.health);
            }
            n.stats = QString::fromUtf8(QJsonDocument(r->stats).toJson(QJsonDocument::Compact));
            n.statsAt = QDateTime::currentSecsSinceEpoch();
            n.health = healthProblem(r->stats);
            ServerStore::upsert(n);
            for (const auto &v: r->stats["services"].toArray()) {
                const auto o = v.toObject();
                logLine(QString("• %1: %2").arg(o["name"].toString(), o["state"].toString() == "active" ? "работает" : o["state"].toString()));
            }
            logLine("• " + healthSummary(r->stats).replace("\n", "\n• "));
            for (const auto &v: r->stats["users"].toArray()) {
                const auto u = v.toObject();
                logLine(QString("• %1: ↓ %2 ↑ %3 (VLESS/XHTTP)").arg(u["name"].toString(),
                    humanSize(u["down"].toVariant().toLongLong()), humanSize(u["up"].toVariant().toLongLong())));
            }
            endTask(true, n.health.isEmpty() ? "Всё работает" : n.health);
        });
    }

    void MyServersDialog::addUser(const ServerNode &s) {
        bool okInput = false;
        const auto name = QInputDialog::getText(this, "Новый пользователь",
            "Для каждого устройства или человека — свой пользователь.\nНапример: Мама, Ноутбук", QLineEdit::Normal, {}, &okInput)
            .trimmed().remove('|');
        if (!okInput || name.isEmpty()) return;
        beginTask(QString("Новый пользователь «%1» на %2").arg(name, s.name));
        runOn(s, {"add-user", name}, [this, name](NodeRun *r, bool ok) {
            if (!ok) return endTask(false, r->error.isEmpty() ? "Не удалось добавить" : r->error);
            ServerStore::upsert(r->node);
            endTask(true, "Пользователь добавлен — покажите ему QR-коды.");
            QList<QPair<QString, QString>> links;
            for (const auto &v: r->result["links"].toArray()) {
                const auto o = v.toObject();
                if (o["user"].toString() == name) links << qMakePair(o["proto"].toString(), o["link"].toString());
            }
            ShowUserLinks(this, QString("%1 · %2").arg(name, r->node.name), links);
        });
    }

    void MyServersDialog::showUsers(const ServerNode &s) {
        beginTask("Пользователи " + s.name);
        runOn(s, {"links"}, [this](NodeRun *r, bool ok) {
            if (!ok) return endTask(false, r->error.isEmpty() ? "Не удалось получить список" : r->error);
            endTask(true, "Список пользователей получен");
            const auto node = r->node;
            const auto result = r->result;
            QMap<QString, QPair<qint64, qint64>> traffic;
            for (const auto &v: QJsonDocument::fromJson(node.stats.toUtf8()).object()["users"].toArray()) {
                const auto u = v.toObject();
                traffic[u["name"].toString()] = {u["down"].toVariant().toLongLong(), u["up"].toVariant().toLongLong()};
            }
            QStringList users;
            for (const auto &v: result["links"].toArray()) {
                const auto u = v.toObject()["user"].toString();
                if (!users.contains(u)) users << u;
            }
            QDialog dlg(this);
            dlg.setWindowTitle("Пользователи «" + node.name + "»");
            auto *lay = new QVBoxLayout(&dlg);
            for (const auto &u: users) {
                auto *row = new QFrame;
                row->setProperty("kombainCard", true);
                auto *rl = new QHBoxLayout(row);
                auto *texts = new QVBoxLayout;
                auto *nm = new QLabel(u);
                nm->setStyleSheet("font-weight: 600; font-size: 14px;");
                texts->addWidget(nm);
                if (traffic.contains(u)) {
                    auto *tr = new QLabel(QString("↓ %1 ↑ %2").arg(humanSize(traffic[u].first), humanSize(traffic[u].second)));
                    tr->setProperty("kombainMuted", true);
                    texts->addWidget(tr);
                }
                rl->addLayout(texts, 1);
                auto *qr = new QPushButton("QR-коды");
                connect(qr, &QPushButton::clicked, &dlg, [this, u, result, node] {
                    QList<QPair<QString, QString>> links;
                    for (const auto &v: result["links"].toArray()) {
                        const auto o = v.toObject();
                        if (o["user"].toString() == u) links << qMakePair(o["proto"].toString(), o["link"].toString());
                    }
                    ShowUserLinks(this, QString("%1 · %2").arg(u, node.name), links);
                });
                rl->addWidget(qr);
                if (users.size() > 1) {
                    auto *del = new QPushButton("Удалить");
                    del->setProperty("kombainDanger", true);
                    connect(del, &QPushButton::clicked, &dlg, [this, &dlg, u, node] {
                        if (QMessageBox::question(this, "Kombain", QString("Удалить «%1»? Его ссылки сразу перестанут работать.").arg(u)) != QMessageBox::Yes) return;
                        dlg.accept();
                        beginTask(QString("Удаляю пользователя «%1»").arg(u));
                        runOn(node, {"remove-user", u}, [this, u](NodeRun *r2, bool ok2) {
                            ServerStore::upsert(r2->node);
                            endTask(ok2, ok2 ? QString("Пользователь «%1» удалён.").arg(u) : (r2->error.isEmpty() ? "Не удалось удалить" : r2->error));
                        });
                    });
                    rl->addWidget(del);
                }
                lay->addWidget(row);
            }
            auto *add = new QPushButton("Добавить пользователя");
            add->setProperty("kombainPrimary", true);
            connect(add, &QPushButton::clicked, &dlg, [this, &dlg, node] { dlg.accept(); addUser(node); });
            lay->addWidget(add);
            dlg.resize(480, 120 + 70 * users.size());
            dlg.exec();
        });
    }

    void MyServersDialog::rotate(const ServerNode &s, bool askPorts) {
        QStringList args{"rotate"};
        if (askPorts) {
            QDialog dlg(this);
            dlg.setWindowTitle("Сменить порты и ключи");
            auto *form = new QFormLayout(&dlg);
            form->addRow(new QLabel("Новые порты (и заодно новые ключи).\nЕсли провайдер режет конкретный порт — смените его."));
            auto mk = [](int v) { auto *b = new QSpinBox; b->setRange(1, 65535); b->setValue(v); return b; };
            auto *pv = mk(s.vpnPort), *px = mk(s.xhPort), *ph = mk(s.hyPort), *pt = mk(s.tuicPort);
            form->addRow("VLESS (TCP)", pv);
            if (s.protocols.contains("xhttp")) form->addRow("XHTTP (TCP)", px);
            if (s.protocols.contains("hy2")) form->addRow("Hysteria2 (UDP)", ph);
            if (s.protocols.contains("tuic")) form->addRow("TUIC (UDP)", pt);
            auto *bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
            bb->button(QDialogButtonBox::Ok)->setText("Сменить");
            connect(bb, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
            connect(bb, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
            form->addRow(bb);
            if (dlg.exec() != QDialog::Accepted) return;
            args << "--port" << QString::number(pv->value());
            if (s.protocols.contains("xhttp")) args << "--xh-port" << QString::number(px->value());
            if (s.protocols.contains("hy2")) args << "--hy-port" << QString::number(ph->value());
            if (s.protocols.contains("tuic")) args << "--tuic-port" << QString::number(pt->value());
        } else if (QMessageBox::question(this, "Сменить ключи",
                       "Сервер получит новые ключи Reality, пароли и пути. Старые ссылки у всех пользователей перестанут работать — "
                       "профили на этом компьютере обновятся сами, остальным нужно будет отправить новые QR-коды.\n\n"
                       "Помогает, если сервер начали блокировать или ссылка попала в чужие руки.") != QMessageBox::Yes) {
            return;
        }
        beginTask("Новые ключи для " + s.name);
        runOn(s, args, [this, args](NodeRun *r, bool ok) {
            if (!ok) return endTask(false, r->error.isEmpty() ? "Не удалось сменить ключи" : r->error);
            auto n = r->node;
            for (int i = 1; i + 1 < args.size(); i += 2) {
                const int v = args[i + 1].toInt();
                if (args[i] == "--port") n.vpnPort = v;
                else if (args[i] == "--xh-port") n.xhPort = v;
                else if (args[i] == "--hy-port") n.hyPort = v;
                else if (args[i] == "--tuic-port") n.tuicPort = v;
            }
            ServerStore::upsert(n);
            if (n.role == "exit") {
                const auto bridge = r->result["bridge"].toString();
                ServerNode entry;
                bool found = false;
                for (const auto &x: ServerStore::all()) if (x.role == "entry" && x.exitId == n.id) { entry = x; found = true; }
                if (!found || bridge.isEmpty()) return endTask(true, "Ключи заменены.");
                logLine("── Переключаю входной сервер " + entry.name + " на новые ключи");
                runOn(entry, {"set-exit", "--exit-link", bridge}, [this](NodeRun *r2, bool ok2) {
                    ServerStore::upsert(r2->node);
                    endTask(ok2, ok2 ? "Ключи выходного сервера заменены, каскад продолжает работать." : (r2->error.isEmpty() ? "Входной сервер не переключился" : r2->error));
                });
                return;
            }
            QString group = n.name;
            if (n.role == "entry") {
                bool f = false;
                const auto ex = ServerStore::get(n.exitId, &f);
                if (f) group = n.name + " → " + ex.name;
            }
            importLinks(n, group, r->result);
            ServerStore::upsert(n);
            endTask(true, "Ключи заменены, профили обновлены. Другим пользователям отправьте новые QR-коды.");
        });
    }

    void MyServersDialog::uninstall(const ServerNode &s) {
        if (QMessageBox::question(this, "Удалить Kombain с сервера",
                QString("Остановить и удалить все службы Kombain на «%1»? Профили этого сервера перестанут работать.").arg(s.name)) != QMessageBox::Yes) return;
        beginTask("Удаляю Kombain с " + s.name);
        runOn(s, {"uninstall"}, [this](NodeRun *r, bool ok) {
            if (!ok) return endTask(false, r->error.isEmpty() ? "Не удалось удалить" : r->error);
            ServerStore::remove(r->node.id);
            endTask(true, "Сервер очищен и убран из списка.");
        });
    }

    QWidget *MyServersDialog::makeCard(const ServerNode &s) {
        auto *card = new QFrame;
        card->setProperty("kombainCard", true);
        auto *l = new QVBoxLayout(card);
        auto *role = new QLabel(s.role == "entry" ? "ВХОД КАСКАДА" : s.role == "exit" ? "ВЫХОД КАСКАДА" : "ОДНА НОДА");
        role->setProperty("kombainAccent", true);
        role->setStyleSheet("font-size: 11px; letter-spacing: 1px;");
        auto *name = new QLabel(s.name);
        name->setStyleSheet("font-size: 17px; font-weight: 700;");
        auto *meta = new QLabel(s.host + " · " + InstallArgsProtocolsLabel(s.protocols));
        meta->setProperty("kombainMuted", true);
        l->addWidget(role);
        l->addWidget(name);
        l->addWidget(meta);
        const auto st = QJsonDocument::fromJson(s.stats.toUtf8()).object();
        QString healthText;
        QString dot = "#9AA9AC";
        if (st.isEmpty() && s.health.isEmpty()) healthText = "Ещё не проверялся — нажмите «Проверить»";
        else {
            dot = s.health.isEmpty() ? "#2FE3A6" : "#FF6B6B";
            const qint64 ago = QDateTime::currentSecsSinceEpoch() - s.statsAt;
            const QString when = ago < 60 ? "только что" : ago < 3600 ? QString("%1 мин назад").arg(ago / 60)
                                       : ago < 86400 ? QString("%1 ч назад").arg(ago / 3600) : QString("%1 дн назад").arg(ago / 86400);
            healthText = (s.health.isEmpty() ? "Работает" : s.health) + " · проверено " + when;
        }
        auto *health = new QLabel(QString("<span style='color:%1'>●</span>&nbsp; %2").arg(dot, healthText.toHtmlEscaped()));
        l->addWidget(health);
        if (!st.isEmpty()) {
            auto *sum = new QLabel(healthSummary(st));
            sum->setProperty("kombainMuted", true);
            l->addWidget(sum);
        }
        auto *row = new QHBoxLayout;
        row->addStretch();
        auto btn = [&](const QString &text, const std::function<void()> &fn) {
            auto *b = new QPushButton(text);
            connect(b, &QPushButton::clicked, this, [this, fn] {
                if (running) { QMessageBox::information(this, "Kombain", "Дождитесь окончания текущей операции"); return; }
                fn();
            });
            row->addWidget(b);
            return b;
        };
        const ServerNode node = s;
        if (s.role != "exit") {
            btn("Профили", [this, node] { refreshProfiles(node); });
            btn("Пользователи", [this, node] { showUsers(node); });
        }
        btn("Проверить", [this, node] { checkServer(node); });
        auto *more = new QPushButton("Ещё");
        auto *menu = new QMenu(more);
        menu->addAction("Сменить ключи", this, [this, node] { if (!running) rotate(node, false); });
        menu->addAction("Сменить порты и ключи", this, [this, node] { if (!running) rotate(node, true); });
        menu->addSeparator();
        menu->addAction("Удалить Kombain с сервера", this, [this, node] { if (!running) uninstall(node); });
        menu->addAction("Убрать из списка (сервер не трогать)", this, [this, node] {
            ServerStore::remove(node.id);
            reloadList();
        });
        more->setMenu(menu);
        row->addWidget(more);
        l->addLayout(row);
        return card;
    }

    void MyServersDialog::reloadList() {
        while (auto *item = listLayout->takeAt(0)) {
            if (auto *w = item->widget()) w->deleteLater();
            delete item;
        }
        const auto servers = ServerStore::all();
        if (servers.isEmpty()) {
            auto *empty = new QLabel("Пока нет серверов, поднятых через Kombain.");
            empty->setProperty("kombainMuted", true);
            listLayout->addWidget(empty);
        }
        for (const auto &s: servers) listLayout->addWidget(makeCard(s));
    }

} // namespace Kombain
