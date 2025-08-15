from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QSpinBox, QDoubleSpinBox, QPushButton,
    QTextEdit, QHBoxLayout, QGroupBox, QApplication
)
from PyQt5.QtCore import Qt
import threading
import numpy as np
import os

class NNLayout:
    """
    Zakładka do trenowania i oceny sieci neuronowej.
    Umożliwia konfigurację hiperparametrów, trenowanie, ocenę i dobór progu.
    """
    def build(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Grupa parametrów sieci
        params_group = QGroupBox("Parametry sieci NN")
        params_layout = QVBoxLayout()
        
        self.lr_input = QDoubleSpinBox()
        self.lr_input.setRange(0.0001, 1.0)
        self.lr_input.setSingleStep(0.0001)
        self.lr_input.setValue(0.001)
        params_layout.addWidget(QLabel("Learning rate:"))
        params_layout.addWidget(self.lr_input)
        
        self.epochs_input = QSpinBox()
        self.epochs_input.setRange(1, 1000)
        self.epochs_input.setValue(20)
        params_layout.addWidget(QLabel("Epochs:"))
        params_layout.addWidget(self.epochs_input)
        
        self.batch_input = QSpinBox()
        self.batch_input.setRange(1, 1024)
        self.batch_input.setValue(32)
        params_layout.addWidget(QLabel("Batch size:"))
        params_layout.addWidget(self.batch_input)
        
        self.threshold_input = QDoubleSpinBox()
        self.threshold_input.setRange(0.0, 1.0)
        self.threshold_input.setSingleStep(0.01)
        self.threshold_input.setValue(0.5)
        params_layout.addWidget(QLabel("Threshold:"))
        params_layout.addWidget(self.threshold_input)
        
        params_group.setLayout(params_layout)
        layout.addWidget(params_group)
        
        # Przyciski akcji
        btn_layout = QHBoxLayout()
        self.train_btn = QPushButton("Trenuj NN")
        self.eval_btn = QPushButton("Oceń model")
        btn_layout.addWidget(self.train_btn)
        btn_layout.addWidget(self.eval_btn)
        layout.addLayout(btn_layout)
        
        # Widok wyników
        self.results_view = QTextEdit()
        self.results_view.setReadOnly(True)
        layout.addWidget(self.results_view)
        
        # Połączenia
        self.train_btn.clicked.connect(self._on_train)
        self.eval_btn.clicked.connect(self._on_evaluate)
        
        # Kontrolki do zwrócenia
        controls = {
            'train_btn': self.train_btn,
            'eval_btn': self.eval_btn,
            'lr_input': self.lr_input,
            'epochs_input': self.epochs_input,
            'batch_input': self.batch_input,
            'threshold_input': self.threshold_input,
            'results_view': self.results_view,
        }
        return widget, controls

    def _on_train(self):
        """Obsługa treningu sieci w wątku, wyświetlanie postępu."""
        lr = self.lr_input.value()
        epochs = self.epochs_input.value()
        batch = self.batch_input.value()
        self.results_view.append(f"Rozpoczynam trening: lr={lr}, epochs={epochs}, batch={batch}")
        # TODO: uruchom rzeczywisty trening w tle
        threading.Thread(target=self._train_model, args=(lr, epochs, batch), daemon=True).start()

    def _train_model(self, lr, epochs, batch):
        # Placeholder dla implementacji
        import time
        for i in range(1, epochs+1):
            time.sleep(0.1)
            self.results_view.append(f"Epoka {i}/{epochs} ukończona")
        self.results_view.append("Trening zakończony")

    def _on_evaluate(self):
        """Obsługa oceny modelu na zbiorze testowym."""
        threshold = self.threshold_input.value()
        self.results_view.append(f"Oceniam model z progiem {threshold}")
        # TODO: prawdziwa ewaluacja i wyświetlenie metryk
        # Na razie symulacja
        import random
        acc = round(random.uniform(0.7, 0.99), 4)
        auc = round(random.uniform(0.7, 0.99), 4)
        self.results_view.append(f"Accuracy: {acc}, AUC: {auc}")

# Test uruchomienia zakładki samodzielnie
if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    w = NNLayout().build()[0]
    w.show()
    sys.exit(app.exec_())
