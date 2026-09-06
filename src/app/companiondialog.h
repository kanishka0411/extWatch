#pragma once

#include <QDialog>

class QLabel;
class QPlainTextEdit;

namespace extwatch {

class CompanionServer;

// Guides the user through installing the companion extension: registers the native messaging
// host for every browser on the machine, extracts the extension files, and shows live status.
class CompanionDialog : public QDialog {
    Q_OBJECT
public:
    CompanionDialog(const QString& dataDir, CompanionServer* server, QWidget* parent = nullptr);

private:
    void registerAndOpen();
    void refreshStatus();

    QString m_dataDir;
    CompanionServer* m_server;
    QLabel* m_status = nullptr;
    QPlainTextEdit* m_log = nullptr;
    QLabel* m_folder = nullptr;
};

}  // namespace extwatch
