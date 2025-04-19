import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QTextEdit, QLineEdit, 
                            QPushButton, QSpinBox, QTabWidget, QGraphicsScene, 
                            QGraphicsView, QSplitter, QGridLayout, QToolBar)
from PyQt6.QtCore import Qt, QRectF, QPoint
from PyQt6.QtGui import QFont, QPen, QBrush, QColor, QPainter, QAction, QIcon

def vec_xor(vec1, vec2):
    """
    Выполняет побитовую операцию XOR между элементами двух векторов разной длины.
    Более короткий вектор дополняется нулями до длины большего.
    """
    result = []
    max_len = max(len(vec1), len(vec2))
    
    for i in range(max_len):
        v1 = vec1[i] if i < len(vec1) else 0
        v2 = vec2[i] if i < len(vec2) else 0
        result.append(v1 ^ v2)
    
    return result

def vec_invert(vect):
    """
    Выполняет побитовую инверсию каждого элемента вектора.
    
    Args:
        vect: Исходный вектор байтов
    
    Returns:
        Новый вектор с инвертированными битами, ограниченными 8 битами (0-255)
    """
    return [~x & 0xFF for x in vect]  # Маска 0xFF для ограничения результата одним байтом

def bit_left(vect):
    """
    Выполняет побитовый сдвиг влево для каждого элемента вектора.
    
    Args:
        vect: Исходный вектор байтов
    
    Returns:
        Новый вектор со сдвинутыми влево битами, ограниченными 8 битами (0-255)
    """
    return [(x << 1) & 0xFF for x in vect]  # Маска для ограничения результата одним байтом

def permute_word(word, key):
    """
    Выполняет перестановку элементов вектора на основе ключа.
    
    Args:
        word: Исходный вектор байтов
        key: Ключ перестановки (целое число)
    
    Returns:
        Новый вектор с переставленными элементами
    """
    word = word.copy()  # Создаем копию, чтобы не изменять оригинал
    for i in range(len(word)):
        # Вычисляем новую позицию элемента, используя ключ
        new_index = (i + key) % len(word)
        # Меняем местами элементы
        word[i], word[new_index] = word[new_index], word[i]
    return word

def f(right, key):
    """
    Функция Фейстеля - основная функция преобразования в сети.
    
    Args:
        right: Правая половина блока
        key: Ключ раунда
    
    Returns:
        Преобразованный вектор для операции XOR с левой половиной блока
    """
    # Последовательно применяем XOR с ключом, инверсию и побитовый сдвиг влево
    return bit_left(vec_invert(vec_xor(right, key)))

def keys_gen(key, decrypt, rounds):
    """
    Генерирует последовательность ключей для каждого раунда шифрования/дешифрования.
    
    Args:
        key: Базовый ключ шифрования
        decrypt: Флаг режима (True для дешифрования, False для шифрования)
        rounds: Количество раундов шифрования
    
    Returns:
        Список ключей для всех раундов
    """
    res = []
    # Генерируем уникальный ключ для каждого раунда
    for i in range(rounds):
        res.append(permute_word(key.copy(), i))
    
    # Для дешифрования используем ключи в обратном порядке
    if decrypt:
        res.reverse()
    return res

def crypt_round(block, round_key):
    """
    Выполняет один раунд шифрования в сети Фейстеля.
    
    Args:
        block: Блок данных для шифрования
        round_key: Ключ текущего раунда
    
    Returns:
        Преобразованный блок после одного раунда
    """
    # Разделяем блок на левую и правую части
    left = block[:len(block)//2]
    right = block[len(block)//2:]
    
    # Применяем функцию Фейстеля к правой части и выполняем XOR с левой частью
    new_right = vec_xor(left, f(right.copy(), round_key))
    
    # Новый блок: старая правая часть становится левой, а результат XOR - новой правой
    return right + new_right

def crypt_block(block, key, decrypt, rounds):
    """
    Шифрует или дешифрует блок данных с использованием сети Фейстеля.
    
    Args:
        block: Блок данных для шифрования/дешифрования
        key: Ключ шифрования
        decrypt: Флаг режима (True для дешифрования, False для шифрования)
        rounds: Количество раундов шифрования
    
    Returns:
        Зашифрованный или дешифрованный блок данных
    """
    # Генерируем ключи для всех раундов
    keys = keys_gen(key, decrypt, rounds)
    
    # Выполняем указанное количество раундов шифрования
    for round_key in keys:
        block = crypt_round(block, round_key)
    
    # Выполняем финальную перестановку (меняем местами левую и правую части)
    left = block[:len(block)//2]
    right = block[len(block)//2:]
    return right + left

def pad_block(block):
    """Дополняет блок до четной длины, если необходимо"""
    if len(block) % 2 != 0:
        return block + [0]  # Добавляем нулевой байт
    return block

class FeistelBlockItem:
    """Класс для визуализации блока данных в сети Фейстеля"""
    
    def __init__(self, scene, x, y, width, height, left_data, right_data, title=""):
        self.scene = scene
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.left_data = left_data
        self.right_data = right_data
        self.title = title
        
        self.draw()
        
    def draw(self):
        # Рисуем общую рамку
        self.scene.addRect(self.x, self.y, self.width, self.height, 
                           QPen(Qt.GlobalColor.black), QBrush(Qt.GlobalColor.white))
        
        # Рисуем разделение на левую и правую части
        self.scene.addLine(self.x + self.width/2, self.y, 
                           self.x + self.width/2, self.y + self.height, 
                           QPen(Qt.GlobalColor.black))
        
        # Добавляем заголовок
        if self.title:
            title_item = self.scene.addText(self.title, QFont("Arial", 10))
            title_item.setPos(self.x + self.width/2 - title_item.boundingRect().width()/2, 
                             self.y - 20)
        
        # Отображаем данные левой и правой частей
        left_text = self.format_data(self.left_data)
        right_text = self.format_data(self.right_data)
        
        left_item = self.scene.addText(left_text, QFont("Courier", 8))
        right_item = self.scene.addText(right_text, QFont("Courier", 8))
        
        left_item.setPos(self.x + 5, self.y + 5)
        right_item.setPos(self.x + self.width/2 + 5, self.y + 5)
    
    def format_data(self, data):
        """Форматирует данные для отображения"""
        if isinstance(data, list):
            # Попытка преобразовать в читаемую строку
            try:
                text = bytes(data).decode('utf-8', errors='replace')
                hex_repr = ' '.join([f'{b:02x}' for b in data])
                return f"{text}\n{hex_repr}"
            except:
                return str(data)
        return str(data)

class FeistelRoundVisualizer:
    """Класс для визуализации одного раунда сети Фейстеля"""
    
    def __init__(self, scene, x, y, width, height, round_num, prev_state, curr_state, round_key):
        self.scene = scene
        self.x = x
        self.y = y
        self.width = width
        self.height = height
        self.round_num = round_num
        self.prev_state = prev_state
        self.curr_state = curr_state
        self.round_key = round_key
        
        self.draw()
    
    def draw(self):
        # Рисуем заголовок раунда
        title = f"Раунд {self.round_num}"
        title_item = self.scene.addText(title, QFont("Arial", 12, QFont.Weight.Bold))
        title_item.setPos(self.x + 10, self.y + 10)
        
        # Размеры блока данных
        block_width = 200
        block_height = 80
        
        # Отображаем входное состояние (до раунда)
        left_prev = self.prev_state[:len(self.prev_state)//2]
        right_prev = self.prev_state[len(self.prev_state)//2:]
        
        FeistelBlockItem(self.scene, self.x + 50, self.y + 40, 
                        block_width, block_height, 
                        left_prev, right_prev, "До раунда")
        
        # Отображаем выходное состояние (после раунда)
        left_curr = self.curr_state[:len(self.curr_state)//2]
        right_curr = self.curr_state[len(self.curr_state)//2:]
        
        FeistelBlockItem(self.scene, self.x + self.width - block_width - 50, 
                        self.y + 40, block_width, block_height, 
                        left_curr, right_curr, "После раунда")
        
        # Отображаем ключ раунда
        key_text = f"Ключ раунда: {bytes(self.round_key).decode('utf-8', errors='replace')}"
        key_item = self.scene.addText(key_text, QFont("Courier", 9))
        key_item.setPos(self.x + self.width/2 - key_item.boundingRect().width()/2, 
                       self.y + self.height - 30)
        
        # Рисуем стрелку от входного состояния к выходному
        arrow_y = self.y + 40 + block_height/2
        self.scene.addLine(self.x + 50 + block_width, arrow_y, 
                          self.x + self.width - 50 - block_width, arrow_y, 
                          QPen(Qt.GlobalColor.black, 2))
        
        # Добавляем наконечник стрелки
        arrow_size = 10
        arrow_x = self.x + self.width - 50 - block_width
        self.scene.addLine(arrow_x, arrow_y, 
                          arrow_x - arrow_size, arrow_y - arrow_size, 
                          QPen(Qt.GlobalColor.black, 2))
        self.scene.addLine(arrow_x, arrow_y, 
                          arrow_x - arrow_size, arrow_y + arrow_size, 
                          QPen(Qt.GlobalColor.black, 2))

class ZoomableGraphicsView(QGraphicsView):
    def __init__(self, scene):
        super().__init__(scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        
        # Начальный масштаб
        self._zoom = 1
        
    def wheelEvent(self, event):
        """Обработка события прокрутки колеса мыши для масштабирования"""
        # Определение направления прокрутки
        factor = 1.2
        if event.angleDelta().y() < 0:
            factor = 1.0 / factor
        
        # Ограничение масштаба
        curr_zoom = self._zoom * factor
        if 0.2 <= curr_zoom <= 5:
            self._zoom = curr_zoom
            self.scale(factor, factor)
    
    def fitInView(self):
        """Подстраивает вид так, чтобы вся сцена была видна"""
        self.resetTransform()
        self._zoom = 1
        rect = self.scene().sceneRect()
        viewrect = self.viewport().rect()
        xratio = viewrect.width() / rect.width()
        yratio = viewrect.height() / rect.height()
        factor = min(xratio, yratio)
        self.scale(factor, factor)
        self._zoom = factor
    
    def zoomIn(self):
        """Увеличивает масштаб"""
        factor = 1.2
        curr_zoom = self._zoom * factor
        if curr_zoom <= 5:
            self._zoom = curr_zoom
            self.scale(factor, factor)
    
    def zoomOut(self):
        """Уменьшает масштаб"""
        factor = 1.0 / 1.2
        curr_zoom = self._zoom * factor
        if curr_zoom >= 0.2:
            self._zoom = curr_zoom
            self.scale(factor, factor)
    
    def resetZoom(self):
        """Сбрасывает масштаб к 100%"""
        self.resetTransform()
        self._zoom = 1

class FeistelVisualizer:
    """Класс для визуализации всего процесса шифрования/дешифрования"""
    
    def __init__(self, block, key, rounds, decrypt=False):
        self.original_block = block.copy()
        self.key = key.copy()
        self.rounds = rounds
        self.decrypt = decrypt
        
        # Генерируем все промежуточные состояния
        self.states = self.generate_states()
    
    def generate_states(self):
        """Генерирует список всех промежуточных состояний блока и ключей"""
        states = []
        keys = keys_gen(self.key.copy(), self.decrypt, self.rounds)
        
        current_block = self.original_block.copy()
        states.append(("Начальный блок", current_block.copy(), None))
        
        for i, round_key in enumerate(keys):
            current_block = crypt_round(current_block, round_key)
            states.append((f"Раунд {i+1}", current_block.copy(), round_key))
        
        # Финальная перестановка
        left = current_block[:len(current_block)//2]
        right = current_block[len(current_block)//2:]
        final_block = right + left
        states.append(("Финальный результат", final_block, None))
        
        return states
    
    def visualize(self, scene):
        """Отображает визуализацию на графической сцене"""
        scene.clear()
        
        # Увеличиваем размеры для лучшей видимости
        width = 1000  # Было 800
        height = 300  # Было 200
        x_margin = 50
        y_margin = 50
        y_offset = y_margin
        
        # Заголовок
        operation_type = "Дешифрование" if self.decrypt else "Шифрование"
        title = f"{operation_type} с использованием сети Фейстеля ({self.rounds} раундов)"
        title_item = scene.addText(title, QFont("Arial", 14, QFont.Weight.Bold))
        title_item.setPos(x_margin, y_offset)
        y_offset += 50
        
        # Отображаем начальное и конечное состояния
        initial_block = self.states[0][1]
        final_block = self.states[-1][1]
        
        left_initial = initial_block[:len(initial_block)//2]
        right_initial = initial_block[len(initial_block)//2:]
        
        left_final = final_block[:len(final_block)//2]
        right_final = final_block[len(final_block)//2:]
        
        block_width = 400  # Было 300
        block_height = 150  # Было 100
        
        # Начальный блок
        FeistelBlockItem(scene, x_margin, y_offset, block_width, block_height, 
                        left_initial, right_initial, "Исходный блок")
        
        # Конечный блок
        FeistelBlockItem(scene, x_margin + width - block_width, y_offset, 
                        block_width, block_height, left_final, right_final, 
                        "Результат")
        
        y_offset += block_height + 50
        
        # Визуализируем каждый раунд
        for i in range(1, len(self.states) - 1):
            prev_state = self.states[i-1][1]
            curr_state = self.states[i][1]
            round_key = self.states[i][2]
            
            FeistelRoundVisualizer(scene, x_margin, y_offset, width, height, 
                                  i, prev_state, curr_state, round_key)
            
            y_offset += height + 30
        
        # Устанавливаем размер сцены
        scene.setSceneRect(0, 0, width + 2*x_margin, y_offset + y_margin)

class FeistelNetworkGUI(QMainWindow):
    """Основной класс графического интерфейса приложения"""
    
    def __init__(self):
        super().__init__()
        self.initUI()
    
    def initUI(self):
        self.setWindowTitle('Сеть Фейстеля - Визуализация')
        self.setGeometry(100, 100, 1000, 800)
        
        # Создаем центральный виджет и общий слой
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Создаем виджет с вкладками
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Вкладка шифрования/дешифрования
        crypt_tab = QWidget()
        self.tabs.addTab(crypt_tab, "Шифрование/Дешифрование")
        
        # Разделим вкладку на две части: контроли и визуализация
        splitter = QSplitter(Qt.Orientation.Vertical)
        crypt_layout = QVBoxLayout(crypt_tab)
        crypt_layout.addWidget(splitter)
        
        # Контейнер для элементов управления
        controls_widget = QWidget()
        controls_layout = QGridLayout(controls_widget)
        splitter.addWidget(controls_widget)
        
        # Поле ввода текста
        controls_layout.addWidget(QLabel("Исходный текст:"), 0, 0)
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Введите текст для шифрования/дешифрования")
        self.text_input.setText("leshaartamonovdvoeshnik")
        controls_layout.addWidget(self.text_input, 0, 1, 1, 3)
        
        # Поле ввода ключа
        controls_layout.addWidget(QLabel("Ключ:"), 1, 0)
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Введите ключ")
        self.key_input.setText("nezachet")
        controls_layout.addWidget(self.key_input, 1, 1)
        
        # Выбор количества раундов
        controls_layout.addWidget(QLabel("Раунды:"), 1, 2)
        self.rounds_input = QSpinBox()
        self.rounds_input.setRange(1, 20)
        self.rounds_input.setValue(10)
        controls_layout.addWidget(self.rounds_input, 1, 3)
        
        # Кнопки
        self.encrypt_button = QPushButton("Зашифровать")
        self.encrypt_button.clicked.connect(self.encrypt_action)
        controls_layout.addWidget(self.encrypt_button, 2, 1)
        
        self.decrypt_button = QPushButton("Дешифровать")
        self.decrypt_button.clicked.connect(self.decrypt_action)
        controls_layout.addWidget(self.decrypt_button, 2, 2)
        
        # Поле вывода результата
        controls_layout.addWidget(QLabel("Результат:"), 3, 0)
        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        controls_layout.addWidget(self.result_output, 3, 1, 1, 3)
        
        # Графическая сцена для визуализации
        self.scene = QGraphicsScene()
        self.view = ZoomableGraphicsView(self.scene)
        splitter.addWidget(self.view)
        
        # Добавляем панель инструментов для масштабирования
        self.create_zoom_toolbar()
        
        # Устанавливаем начальные размеры сплиттера
        splitter.setSizes([200, 600])
        
        # Вкладка "О программе"
        about_tab = QWidget()
        self.tabs.addTab(about_tab, "О программе")
        
        about_layout = QVBoxLayout(about_tab)
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setHtml("""
        <h1>Визуализация работы сети Фейстеля</h1>
        <p>Данное приложение демонстрирует принцип работы сети Фейстеля - 
        распространенной схемы построения блочных шифров.</p>
        
        <h2>Принцип работы:</h2>
        <ol>
            <li>Входной блок данных делится на две равные части: левую (L) и правую (R).</li>
            <li>В каждом раунде шифрования к правой части применяется функция преобразования F с использованием ключа раунда.</li>
            <li>Результат операции F XOR-ится с левой частью, формируя новую правую часть.</li>
            <li>Старая правая часть становится новой левой частью.</li>
            <li>После последнего раунда выполняется финальная перестановка - обмен левой и правой частей местами.</li>
        </ol>
        
        <h2>Особенности:</h2>
        <ul>
            <li>Дешифрование выполняется тем же алгоритмом, но с обратным порядком ключей.</li>
            <li>Количество раундов влияет на криптостойкость шифра.</li>
            <li>Функция F может различаться в разных реализациях шифров на основе сети Фейстеля.</li>
        </ul>
        """)
        about_layout.addWidget(about_text)
    
    def create_zoom_toolbar(self):
        """Создает панель инструментов для управления масштабом"""
        zoom_toolbar = QToolBar("Масштаб")
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, zoom_toolbar)
        
        # Кнопка "Увеличить"
        zoom_in_action = QAction("Увеличить (+)", self)
        zoom_in_action.triggered.connect(self.view.zoomIn)
        zoom_toolbar.addAction(zoom_in_action)
        
        # Кнопка "Уменьшить"
        zoom_out_action = QAction("Уменьшить (-)", self)
        zoom_out_action.triggered.connect(self.view.zoomOut)
        zoom_toolbar.addAction(zoom_out_action)
        
        # Кнопка "Сбросить масштаб"
        reset_zoom_action = QAction("Сбросить масштаб (100%)", self)
        reset_zoom_action.triggered.connect(self.view.resetZoom)
        zoom_toolbar.addAction(reset_zoom_action)
        
        # Кнопка "Вписать в окно"
        fit_action = QAction("Вписать в окно", self)
        fit_action.triggered.connect(self.view.fitInView)
        zoom_toolbar.addAction(fit_action)
    
    def encrypt_action(self):
        """Обработчик нажатия кнопки 'Зашифровать'"""
        self.process_data(False)
    
    def decrypt_action(self):
        """Обработчик нажатия кнопки 'Дешифровать'"""
        self.process_data(True)
    
    def process_data(self, decrypt=False):
        """Обрабатывает данные и выполняет шифрование/дешифрование"""
        # Получаем данные из полей ввода
        text = self.text_input.toPlainText()
        key = self.key_input.text()
        rounds = self.rounds_input.value()
        
        if not text or not key:
            self.result_output.setText("Ошибка: Пожалуйста, введите текст и ключ")
            return
        
        # Преобразуем в формат для обработки
        block = pad_block(list(text.encode('utf-8')))
        key_data = list(key.encode('utf-8'))
        
        # Шифруем/дешифруем
        result_block = crypt_block(block.copy(), key_data.copy(), decrypt, rounds)
        
        # Отображаем результат
        try:
            result_text = bytes(result_block).decode('utf-8', errors='replace')
            hex_result = ' '.join([f'{b:02x}' for b in result_block])
            self.result_output.setText(f"Текст: {result_text}\nHEX: {hex_result}")
        except:
            hex_result = ' '.join([f'{b:02x}' for b in result_block])
            self.result_output.setText(f"HEX: {hex_result}")
        
        # Визуализируем процесс
        visualizer = FeistelVisualizer(block, key_data, rounds, decrypt)
        visualizer.visualize(self.scene)
        
        # Подгоняем вид для отображения всей сцены
        self.view.fitInView()

def main():
    """
    Запускает GUI-приложение для визуализации работы сети Фейстеля.
    """
    app = QApplication(sys.argv)
    gui = FeistelNetworkGUI()
    gui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
