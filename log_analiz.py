import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox
)
from PyQt5.QtCore import Qt, QObject, pyqtSignal, QThread
import paramiko


class LogTailer(QObject):
    log_signal = pyqtSignal(str)

    def __init__(self, ssh, log_file):
        super().__init__()
        self.ssh = ssh
        self.log_file = log_file
        self.running = True

    def run(self):
        try:
            stdin, stdout, stderr = self.ssh.exec_command(f"tail -f {self.log_file}")
            while self.running:
                for line in stdout:
                    if not self.running:
                        break
                    self.log_signal.emit(line.strip())
        except Exception as e:
            self.log_signal.emit(f"Log takibi sırasında hata oluştu: {e}")

    def stop(self):
        self.running = False


class SSHClientApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ssh = None
        self.log_thread = None
        self.log_tailer = None
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("SSH Client")
        self.setGeometry(200, 200, 900, 600)

        central_widget = QWidget()
        main_layout = QVBoxLayout()
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

        # Başlık
        title_label = QLabel("SSH Client")
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #333;")
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)

        # Hostname giriş alanı
        self.hostname_input = self.create_input_field("Hostname/IP:", main_layout)

        # Port giriş alanı
        self.port_input = self.create_input_field("Port:", main_layout, default_text="22")

        # Kullanıcı adı giriş alanı
        self.username_input = self.create_input_field("Username:", main_layout)

        # Şifre giriş alanı
        self.password_input = self.create_input_field("Password:", main_layout, is_password=True)

        # Bağlan ve Kapat düğmeleri
        button_layout = QHBoxLayout()
        self.connect_button = self.create_button("Bağlan", button_layout, self.connect_ssh, color="#4CAF50")
        self.disconnect_button = self.create_button("Kapat", button_layout, self.disconnect_ssh, color="#F44336")
        main_layout.addLayout(button_layout)

        # Komut giriş alanı
        command_label = QLabel("Komut:")
        command_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        main_layout.addWidget(command_label)
        self.command_input = QTextEdit()
        self.command_input.setFixedHeight(100)
        main_layout.addWidget(self.command_input)

        # Komut Çalıştır düğmesi
        self.execute_button = self.create_button("Komutu Çalıştır", main_layout, self.execute_command, color="#2196F3")

        # Log takip düğmesi ve çıktı alanı
        log_button_layout = QHBoxLayout()
        self.start_log_button = self.create_button("Logları Takip Et", log_button_layout, self.start_log_tailing, color="#FF9800")
        self.stop_log_button = self.create_button("Log Takibini Durdur", log_button_layout, self.stop_log_tailing, color="#9E9E9E")
        self.stop_log_button.setEnabled(False)
        main_layout.addLayout(log_button_layout)

        log_output_label = QLabel("Log Çıktısı:")
        log_output_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        main_layout.addWidget(log_output_label)
        self.log_output_area = QTextEdit()
        self.log_output_area.setReadOnly(True)
        self.log_output_area.setStyleSheet("background-color: #f0f0f0;")
        main_layout.addWidget(self.log_output_area)

        # Sunucu bilgilerini yükle düğmesi
        self.load_config_button = self.create_button("Sunucu Bilgilerini Yükle", main_layout, self.load_server_config, color="#673AB7")

    def create_input_field(self, label_text, layout, default_text="", is_password=False):
        label = QLabel(label_text)
        label.setStyleSheet("font-size: 16px; font-weight: bold;")
        layout.addWidget(label)
        input_field = QLineEdit()
        if default_text:
            input_field.setText(default_text)
        if is_password:
            input_field.setEchoMode(QLineEdit.Password)
        layout.addWidget(input_field)
        return input_field

    def create_button(self, text, layout, callback, color="#2196F3"):
        button = QPushButton(text)
        button.setStyleSheet(f"""
            QPushButton {{
                font-size: 16px;
                font-weight: bold;
                background-color: {color};
                color: white;
                border-radius: 5px;
                padding: 10px;
            }}
            QPushButton:hover {{
                background-color: #0056b3;
            }}
        """)
        button.clicked.connect(callback)
        layout.addWidget(button)
        return button

    def connect_ssh(self):
        hostname = self.hostname_input.text()
        port = int(self.port_input.text())
        username = self.username_input.text()
        password = self.password_input.text()

        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(hostname, port=port, username=username, password=password)
            QMessageBox.information(self, "Başarılı", "SSH bağlantısı kuruldu!")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"SSH bağlantısı başarısız: {e}")

    def disconnect_ssh(self):
        if self.ssh:
            self.stop_log_tailing()
            self.ssh.close()
            self.ssh = None
            QMessageBox.information(self, "Başarılı", "SSH bağlantısı kapatıldı!")

    def execute_command(self):
        if not self.ssh:
            QMessageBox.warning(self, "Uyarı", "Lütfen önce SSH bağlantısı kurun.")
            return

        command = self.command_input.toPlainText().strip()
        if not command:
            QMessageBox.warning(self, "Uyarı", "Lütfen bir komut girin.")
            return

        try:
            stdin, stdout, stderr = self.ssh.exec_command(command)
            output = stdout.read().decode()
            error = stderr.read().decode()
            self.display_command_output(output, error)
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Komut çalıştırılamadı: {e}")

    def display_command_output(self, output, error):
        self.log_output_area.clear()
        if output:
            output_lines = output.splitlines()
            self.log_output_area.append("<b>Komut Çıktısı:</b>")
            for i, line in enumerate(output_lines, 1):
                self.log_output_area.append(f"<b>{i}.</b> {line}")

        if error:
            error_lines = error.splitlines()
            self.log_output_area.append("<b>Hata Çıktısı:</b>")
            for i, line in enumerate(error_lines, 1):
                self.log_output_area.append(f"<font color='red'><b>{i}.</b> {line}</font>")

    def start_log_tailing(self):
        if not self.ssh:
            QMessageBox.warning(self, "Uyarı", "Lütfen önce SSH bağlantısı kurun.")
            return

        log_file = "/var/log/auth.log"
        self.log_tailer = LogTailer(self.ssh, log_file)
        self.log_thread = QThread()
        self.log_tailer.moveToThread(self.log_thread)

        self.log_tailer.log_signal.connect(self.append_log_output)
        self.log_thread.started.connect(self.log_tailer.run)
        self.log_thread.finished.connect(self.log_thread.deleteLater)

        self.log_thread.start()
        self.start_log_button.setEnabled(False)
        self.stop_log_button.setEnabled(True)

    def stop_log_tailing(self):
        if self.log_tailer:
            self.log_tailer.stop()
            self.log_thread.quit()
            self.log_thread.wait()
            self.log_tailer = None
            self.log_thread = None
            self.start_log_button.setEnabled(True)
            self.stop_log_button.setEnabled(False)

    def append_log_output(self, text):
        self.log_output_area.append(text)

    def load_server_config(self):
        try:
            with open("server_config.txt", "r") as file:
                lines = file.readlines()
                if len(lines) >= 4:
                    self.hostname_input.setText(lines[0].strip())
                    self.port_input.setText(lines[1].strip())
                    self.username_input.setText(lines[2].strip())
                    self.password_input.setText(lines[3].strip())
                    QMessageBox.information(self, "Başarılı", "Sunucu bilgileri yüklendi!")
                else:
                    QMessageBox.warning(self, "Hata", "Konfigürasyon dosyası eksik!")
        except FileNotFoundError:
            QMessageBox.critical(self, "Hata", "server_config.txt dosyası bulunamadı!")
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Konfigürasyon yükleme hatası: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SSHClientApp()
    window.show()
    sys.exit(app.exec_())
