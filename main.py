import sys
import sqlite3
import bcrypt
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QStackedWidget, QMessageBox, QListWidget,
                             QListWidgetItem, QFormLayout, QFrame, QSizePolicy)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor

class DatabaseManager:
    def __init__(self, db_name="app_database.db"):
        self.db_name = db_name
        self.init_database()

    def init_database(self):
        """Инициализация базы данных и создание таблиц"""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            
            # Таблица пользователей
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            ''')
            
            # Таблица пользовательских данных
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
            ''')
            
            # Индексы для улучшения производительности
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_data_user_id ON user_data(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
            
            conn.commit()

    def create_user(self, username: str, email: str, password: str) -> bool:
        """Создание нового пользователя"""
        try:
            password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                    (username, email, password_hash)
                )
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            return False

    def authenticate_user(self, username: str, password: str) -> tuple:
        """Аутентификация пользователя"""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT id, username, email, password_hash, created_at, last_login FROM users WHERE username = ?',
                (username,)
            )
            user_data = cursor.fetchone()
            
            if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data[3]):
                # Обновляем время последнего входа
                cursor.execute(
                    'UPDATE users SET last_login = ? WHERE id = ?',
                    (datetime.now().isoformat(), user_data[0])
                )
                conn.commit()
                
                return user_data[0], user_data[1]  # id, username
            return None, None

    def save_user_data(self, user_id: int, title: str, content: str) -> bool:
        """Сохранение данных пользователя"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'INSERT INTO user_data (user_id, title, content) VALUES (?, ?, ?)',
                    (user_id, title, content)
                )
                conn.commit()
                return True
        except Exception as e:
            print(f"Error saving data: {e}")
            return False

    def get_user_data(self, user_id: int) -> list:
        """Получение данных пользователя"""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT id, title, content, created_at FROM user_data WHERE user_id = ? ORDER BY created_at DESC',
                (user_id,)
            )
            return cursor.fetchall()

    def delete_user_data(self, data_id: int, user_id: int) -> bool:
        """Удаление данных пользователя"""
        try:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    'DELETE FROM user_data WHERE id = ? AND user_id = ?',
                    (data_id, user_id)
                )
                conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"Error deleting data: {e}")
            return False

    def user_exists(self, username: str) -> bool:
        """Проверка существования пользователя"""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            return cursor.fetchone() is not None

    def email_exists(self, email: str) -> bool:
        """Проверка существования email"""
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM users WHERE email = ?', (email,))
            return cursor.fetchone() is not None

class AuthWindow(QWidget):
    login_success = pyqtSignal(int, str)  # user_id, username
    
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(40, 40, 40, 40)
        
        # Заголовок
        title = QLabel("Добро пожаловать")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #4CAF50; margin-bottom: 20px;")
        layout.addWidget(title)
        
        # Форма входа
        form_layout = QFormLayout()
        form_layout.setSpacing(10)
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Введите имя пользователя")
        self.username_input.setStyleSheet(self.get_input_style())
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Введите пароль")
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet(self.get_input_style())
        
        form_layout.addRow("Логин:", self.username_input)
        form_layout.addRow("Пароль:", self.password_input)
        
        layout.addLayout(form_layout)
        
        # Кнопки
        buttons_layout = QHBoxLayout()
        
        self.login_btn = QPushButton("Войти")
        self.login_btn.setStyleSheet(self.get_button_style())
        self.login_btn.clicked.connect(self.handle_login)
        
        self.register_btn = QPushButton("Регистрация")
        self.register_btn.setStyleSheet(self.get_button_style("secondary"))
        self.register_btn.clicked.connect(self.show_register_form)
        
        buttons_layout.addWidget(self.login_btn)
        buttons_layout.addWidget(self.register_btn)
        
        layout.addLayout(buttons_layout)
        
        # Форма регистрации (изначально скрыта)
        self.register_widget = QWidget()
        register_layout = QVBoxLayout()
        
        self.reg_username = QLineEdit()
        self.reg_username.setPlaceholderText("Придумайте имя пользователя")
        self.reg_username.setStyleSheet(self.get_input_style())
        
        self.reg_email = QLineEdit()
        self.reg_email.setPlaceholderText("Введите email")
        self.reg_email.setStyleSheet(self.get_input_style())
        
        self.reg_password = QLineEdit()
        self.reg_password.setPlaceholderText("Придумайте пароль")
        self.reg_password.setEchoMode(QLineEdit.Password)
        self.reg_password.setStyleSheet(self.get_input_style())
        
        self.reg_confirm = QLineEdit()
        self.reg_confirm.setPlaceholderText("Подтвердите пароль")
        self.reg_confirm.setEchoMode(QLineEdit.Password)
        self.reg_confirm.setStyleSheet(self.get_input_style())
        
        register_layout.addWidget(QLabel("Имя пользователя:"))
        register_layout.addWidget(self.reg_username)
        register_layout.addWidget(QLabel("Email:"))
        register_layout.addWidget(self.reg_email)
        register_layout.addWidget(QLabel("Пароль:"))
        register_layout.addWidget(self.reg_password)
        register_layout.addWidget(QLabel("Подтверждение пароля:"))
        register_layout.addWidget(self.reg_confirm)
        
        self.register_submit_btn = QPushButton("Зарегистрироваться")
        self.register_submit_btn.setStyleSheet(self.get_button_style())
        self.register_submit_btn.clicked.connect(self.handle_register)
        
        self.back_btn = QPushButton("Назад")
        self.back_btn.setStyleSheet(self.get_button_style("secondary"))
        self.back_btn.clicked.connect(self.show_login_form)
        
        register_buttons = QHBoxLayout()
        register_buttons.addWidget(self.register_submit_btn)
        register_buttons.addWidget(self.back_btn)
        
        register_layout.addLayout(register_buttons)
        self.register_widget.setLayout(register_layout)
        self.register_widget.hide()
        
        layout.addWidget(self.register_widget)
        self.setLayout(layout)
        
    def get_input_style(self):
        return """
            QLineEdit {
                background-color: #3c3c3c;
                border: 2px solid #555;
                border-radius: 8px;
                padding: 12px;
                color: #ffffff;
                font-size: 14px;
                margin: 5px 0;
            }
            QLineEdit:focus {
                border-color: #4CAF50;
            }
        """
    
    def get_button_style(self, style="primary"):
        if style == "primary":
            return """
                QPushButton {
                    background-color: #4CAF50;
                    border: none;
                    color: white;
                    padding: 12px 24px;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #45a049;
                }
                QPushButton:pressed {
                    background-color: #3d8b40;
                }
                QPushButton:disabled {
                    background-color: #666;
                }
            """
        else:
            return """
                QPushButton {
                    background-color: #666;
                    border: none;
                    color: white;
                    padding: 12px 24px;
                    border-radius: 8px;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #777;
                }
                QPushButton:pressed {
                    background-color: #555;
                }
            """
    
    def handle_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        
        if not username or not password:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля")
            return
        
        user_id, username = self.db.authenticate_user(username, password)
        if user_id:
            self.login_success.emit(user_id, username)
        else:
            QMessageBox.warning(self, "Ошибка", "Неверные учетные данные")
    
    def handle_register(self):
        username = self.reg_username.text().strip()
        email = self.reg_email.text().strip()
        password = self.reg_password.text().strip()
        confirm = self.reg_confirm.text().strip()
        
        if not all([username, email, password, confirm]):
            QMessageBox.warning(self, "Ошибка", "Заполните все поля")
            return
        
        if password != confirm:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают")
            return
        
        if len(password) < 6:
            QMessageBox.warning(self, "Ошибка", "Пароль должен содержать минимум 6 символов")
            return
        
        if self.db.user_exists(username):
            QMessageBox.warning(self, "Ошибка", "Пользователь с таким именем уже существует")
            return
        
        if self.db.email_exists(email):
            QMessageBox.warning(self, "Ошибка", "Пользователь с таким email уже существует")
            return
        
        if self.db.create_user(username, email, password):
            QMessageBox.information(self, "Успех", "Регистрация прошла успешно!")
            self.show_login_form()
        else:
            QMessageBox.warning(self, "Ошибка", "Ошибка при регистрации")
    
    def show_register_form(self):
        self.register_widget.show()
        self.username_input.hide()
        self.password_input.hide()
        self.login_btn.hide()
        self.register_btn.hide()
    
    def show_login_form(self):
        self.register_widget.hide()
        self.username_input.show()
        self.password_input.show()
        self.login_btn.show()
        self.register_btn.show()

class MainWindow(QMainWindow):
    def __init__(self, user_id, username):
        super().__init__()
        self.user_id = user_id
        self.username = username
        self.db = DatabaseManager()
        self.init_ui()
        self.load_data()
        
    def init_ui(self):
        self.setWindowTitle(f"Мое приложение - {self.username}")
        self.setGeometry(100, 100, 900, 600)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
            }
        """)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        layout = QHBoxLayout()
        central_widget.setLayout(layout)
        
        # Боковая панель
        sidebar = QFrame()
        sidebar.setFixedWidth(250)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #333;
                border-right: 2px solid #444;
            }
        """)
        
        sidebar_layout = QVBoxLayout()
        sidebar_layout.setSpacing(10)
        sidebar_layout.setContentsMargins(15, 20, 15, 20)
        
        # Заголовок боковой панели
        user_label = QLabel(f"Пользователь: {self.username}")
        user_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #4CAF50;")
        sidebar_layout.addWidget(user_label)
        
        sidebar_layout.addSpacing(20)
        
        # Кнопка выхода
        logout_btn = QPushButton("Выйти")
        logout_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                border: none;
                color: white;
                padding: 10px;
                border-radius: 5px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #da190b;
            }
        """)
        logout_btn.clicked.connect(self.close)
        sidebar_layout.addWidget(logout_btn)
        
        sidebar_layout.addStretch()
        sidebar.setLayout(sidebar_layout)
        layout.addWidget(sidebar)
        
        # Основная область
        main_area = QWidget()
        main_layout = QVBoxLayout()
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Форма для добавления данных
        form_frame = QFrame()
        form_frame.setStyleSheet("""
            QFrame {
                background-color: #333;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        form_layout = QVBoxLayout()
        
        title_label = QLabel("Добавить новую запись:")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        form_layout.addWidget(title_label)
        
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("Заголовок")
        self.title_input.setStyleSheet("""
            QLineEdit {
                background-color: #3c3c3c;
                border: 2px solid #555;
                border-radius: 5px;
                padding: 10px;
                color: #ffffff;
                font-size: 14px;
            }
        """)
        form_layout.addWidget(self.title_input)
        
        self.content_input = QTextEdit()
        self.content_input.setPlaceholderText("Содержание...")
        self.content_input.setStyleSheet("""
            QTextEdit {
                background-color: #3c3c3c;
                border: 2px solid #555;
                border-radius: 5px;
                padding: 10px;
                color: #ffffff;
                font-size: 14px;
                min-height: 100px;
            }
        """)
        form_layout.addWidget(self.content_input)
        
        self.save_btn = QPushButton("Сохранить")
        self.save_btn.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                border: none;
                color: white;
                padding: 12px;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
        """)
        self.save_btn.clicked.connect(self.save_data)
        form_layout.addWidget(self.save_btn)
        
        form_frame.setLayout(form_layout)
        main_layout.addWidget(form_frame)
        
        # Список записей
        records_label = QLabel("Мои записи:")
        records_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        main_layout.addWidget(records_label)
        
        self.records_list = QListWidget()
        self.records_list.setStyleSheet("""
            QListWidget {
                background-color: #333;
                border: 2px solid #444;
                border-radius: 5px;
                padding: 5px;
            }
            QListWidget::item {
                background-color: #3c3c3c;
                border-radius: 5px;
                padding: 10px;
                margin: 5px;
            }
            QListWidget::item:selected {
                background-color: #4CAF50;
            }
        """)
        main_layout.addWidget(self.records_list)
        
        main_area.setLayout(main_layout)
        layout.addWidget(main_area)
        
        # Устанавливаем пропорции
        layout.setStretch(0, 1)
        layout.setStretch(1, 3)
    
    def save_data(self):
        title = self.title_input.text().strip()
        content = self.content_input.toPlainText().strip()
        
        if not title or not content:
            QMessageBox.warning(self, "Ошибка", "Заполните все поля")
            return
        
        if self.db.save_user_data(self.user_id, title, content):
            QMessageBox.information(self, "Успех", "Данные сохранены!")
            self.title_input.clear()
            self.content_input.clear()
            self.load_data()
        else:
            QMessageBox.warning(self, "Ошибка", "Ошибка при сохранении данных")
    
    def load_data(self):
        self.records_list.clear()
        data = self.db.get_user_data(self.user_id)
        
        for item in data:
            data_id, title, content, created_at = item
            widget = QWidget()
            layout = QVBoxLayout()
            
            title_label = QLabel(title)
            title_label.setStyleSheet("font-weight: bold; color: #4CAF50;")
            
            content_label = QLabel(content[:100] + "..." if len(content) > 100 else content)
            content_label.setWordWrap(True)
            content_label.setStyleSheet("color: #ccc;")
            
            date_label = QLabel(f"Создано: {created_at}")
            date_label.setStyleSheet("font-size: 12px; color: #888;")
            
            layout.addWidget(title_label)
            layout.addWidget(content_label)
            layout.addWidget(date_label)
            layout.setContentsMargins(10, 5, 10, 5)
            
            widget.setLayout(layout)
            
            list_item = QListWidgetItem(self.records_list)
            list_item.setSizeHint(widget.sizeHint())
            self.records_list.addItem(list_item)
            self.records_list.setItemWidget(list_item, widget)
            
            # Добавляем контекстное меню для удаления
            list_item.setData(Qt.UserRole, data_id)

class AppManager(QStackedWidget):
    def __init__(self):
        super().__init__()
        self.db = DatabaseManager()
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("Мое приложение")
        self.setGeometry(100, 100, 500, 400)
        
        # Устанавливаем темную тему
        self.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
            }
        """)
        
        # Окно авторизации
        self.auth_window = AuthWindow()
        self.auth_window.login_success.connect(self.handle_login_success)
        self.addWidget(self.auth_window)
        
        # Показываем окно авторизации
        self.setCurrentIndex(0)
    
    def handle_login_success(self, user_id, username):
        # Создаем и показываем главное окно
        self.main_window = MainWindow(user_id, username)
        self.addWidget(self.main_window)
        self.setCurrentIndex(1)
        self.setWindowTitle(f"Мое приложение - {username}")
        self.resize(900, 600)

def main():
    app = QApplication(sys.argv)
    
    # Устанавливаем стиль для всего приложения
    app.setStyle('Fusion')
    
    # Создаем палитру для темной темы
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(43, 43, 43))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
    palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)
    
    window = AppManager()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()