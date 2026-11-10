#pragma once
// Kombain «Мои серверы»: deploy and manage own VPN servers over SSH (same kombain-node.sh as the phone app).

#include <QDialog>
#include <QJsonObject>
#include <QList>
#include <QObject>
#include <QProcess>
#include <QString>
#include <QStringList>

class QPlainTextEdit;
class QVBoxLayout;
class QLabel;
class QProgressBar;
class QFrame;

namespace Kombain {

    struct ServerNode {
        QString id, name, host, user = "root", password, key, sni = "www.microsoft.com", hostKey;
        int sshPort = 22;
        QString role = "single"; // single | entry | exit
        QString exitId;
        QString protocols = "vless,xhttp,hy2";
        int vpnPort = 443, xhPort = 8443, hyPort = 443, tuicPort = 8443, tgPort = 9443;
        int groupId = -1;
        QString stats; // last `stats` JSON
        qint64 statsAt = 0;
        QString health;

        QJsonObject toJson() const;
        static ServerNode fromJson(const QJsonObject &o);
        bool hasTelegram() const { return protocols.split(',').contains("tg"); }
    };

    class ServerStore {
    public:
        static QList<ServerNode> all();
        static void saveAll(const QList<ServerNode> &list);
        static void upsert(const ServerNode &n);
        static void remove(const QString &id);
        static ServerNode get(const QString &id, bool *ok = nullptr);
    };

    /** One run of kombain-node.sh on a server (through the bundled kombain-node helper). */
    class NodeRun : public QObject {
        Q_OBJECT
    public:
        NodeRun(const ServerNode &node, const QStringList &args, QObject *parent = nullptr);
        void start();

        ServerNode node;
        QJsonObject result; // KB_RESULT
        QJsonObject stats;  // KB_STATS
        QString error;

    signals:
        void line(const QString &text);
        void finished(bool ok);

    private:
        QStringList args;
        QProcess proc;
        QByteArray buffer;
        void handleLine(const QString &l);
    };

    class MyServersDialog : public QDialog {
        Q_OBJECT
    public:
        explicit MyServersDialog(QWidget *parent = nullptr);

        // shared log of the current / last operation
        void logLine(const QString &text);
        void beginTask(const QString &title);
        void endTask(bool ok, const QString &message);
        bool busy() const { return running; }

        void runOn(const ServerNode &node, const QStringList &args, const std::function<void(NodeRun *, bool)> &done);
        void installSingle(ServerNode node);
        void installCascade(ServerNode exitNode, ServerNode entryNode);
        void connectExisting(ServerNode node);
        void reloadList();

    private:
        QVBoxLayout *listLayout = nullptr;
        QFrame *logCard = nullptr;
        QLabel *logTitle = nullptr;
        QProgressBar *logProgress = nullptr;
        QPlainTextEdit *logView = nullptr;
        bool running = false;

        QWidget *makeCard(const ServerNode &s);
        void refreshProfiles(const ServerNode &s);
        void checkServer(const ServerNode &s);
        void showUsers(const ServerNode &s);
        void addUser(const ServerNode &s);
        void rotate(const ServerNode &s, bool askPorts);
        void uninstall(const ServerNode &s);
        void enableTelegram(const ServerNode &s);
        void disableTelegram(const ServerNode &s);
        void importLinks(ServerNode &node, const QString &groupName, const QJsonObject &result, bool firstUserOnly = true);
    };

    void ShowUserLinks(QWidget *parent, const QString &title, const QList<QPair<QString, QString>> &protoLinks);
    void ShowTelegram(QWidget *parent, const QString &serverName, const QString &tgLink);

    QString InstallArgsProtocolsLabel(const QString &protocols);
}
