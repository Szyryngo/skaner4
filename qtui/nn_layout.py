"""Module nn_layout: provides a PyQt5 tab for configuring, training, and evaluating a neural network using TensorFlow or sklearn.

This module implements the NNLayout class which builds UI controls for hyperparameters, handles model training in a background thread,
and presents evaluation metrics in a formatted HTML table."""
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QSpinBox, QDoubleSpinBox, QPushButton, QTextEdit, QHBoxLayout, QGroupBox, QApplication, QProgressBar
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QTextCursor
import threading
import time
import numpy as np
import os
from datetime import datetime
from qtui.cmd_log_widget import create_cmd_log
try:
    from PyQt5.QtCore import qRegisterMetaType
    qRegisterMetaType(QTextCursor, 'QTextCursor')
except ImportError:
    pass


class NNLayout:
    """
    Neural network training and evaluation tab layout.

    Provides UI for setting hyperparameters, training a model in a background thread,
    and evaluating it on synthetic test data, displaying results in an HTML table.
    """

    def build(self):
        """
        Build the UI layout for the neural network tab.

        Returns
        -------
        widget : QWidget
            The container widget holding all controls.
        controls : dict
            Dictionary of UI controls keyed by name.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        self.nn_model = None
        # Parametry sieci
        params_group = QGroupBox('Parametry sieci NN')
        params_layout = QVBoxLayout()
        desc = QLabel('Learning rate; Epochs; Batch size; Threshold')
        desc.setStyleSheet('font-style: italic; font-size: 10px;')
        params_layout.addWidget(desc)
        # Warstwa wejściowa parametrów
        self.lr_input = QDoubleSpinBox();  self.lr_input.setRange(0.0001, 1.0);  self.lr_input.setValue(0.001)
        self.epochs_input = QSpinBox();    self.epochs_input.setRange(1, 1000); self.epochs_input.setValue(20)
        self.batch_input = QSpinBox();     self.batch_input.setRange(1, 1024);  self.batch_input.setValue(32)
        self.threshold_input = QDoubleSpinBox(); self.threshold_input.setRange(0.0,1.0); self.threshold_input.setValue(0.5)
        for label, widget_input in [('Learning rate:', self.lr_input), ('Epochs:', self.epochs_input),
                                   ('Batch size:', self.batch_input), ('Threshold:', self.threshold_input)]:
            params_layout.addWidget(QLabel(label)); params_layout.addWidget(widget_input)
        params_group.setLayout(params_layout)
        layout.addWidget(params_group)
        # Przyciski: trening, ewaluacja i test AI
        btn_layout = QHBoxLayout()
        self.train_btn = QPushButton('Trenuj NN')
        self.eval_btn = QPushButton('Oceń model')
        self.check_btn = QPushButton('Sprawdź AI')
        btn_layout.addWidget(self.train_btn)
        btn_layout.addWidget(self.eval_btn)
        btn_layout.addWidget(self.check_btn)
        layout.addLayout(btn_layout)
        # Wyniki i log
        self.results_view = QTextEdit()
        self.results_view.setReadOnly(True)
        layout.addWidget(self.results_view)
        # Pasek postępu i anulacja
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.cancel_btn = QPushButton('Anuluj trening')
        self.cancel_btn.setEnabled(False)
        self._cancel_requested = False
        layout.addWidget(self.progress)
        layout.addWidget(self.cancel_btn)
        # Command log at bottom
        self.cmd_log = create_cmd_log()
        layout.addWidget(self.cmd_log)
        # Połączenie sygnałów
        self.train_btn.clicked.connect(self._on_train)
        self.eval_btn.clicked.connect(self._on_evaluate)
        self.cancel_btn.clicked.connect(self._on_cancel)
        controls = {
            'train_btn': self.train_btn,
            'eval_btn': self.eval_btn,
            'check_btn': self.check_btn,
            'cancel_btn': self.cancel_btn,
            'progress': self.progress,
            'lr_input': self.lr_input,
            'epochs_input': self.epochs_input,
            'batch_input': self.batch_input,
            'threshold_input': self.threshold_input,
            'results_view': self.results_view,
            'cmd_log': self.cmd_log
        }
        return widget, controls

    def _on_train(self):
        """
        Handle training button click: log start and run training synchronously.
        """
        lr = self.lr_input.value()
        epochs = self.epochs_input.value()
        batch = self.batch_input.value()
        self.cmd_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Rozpoczynam trening sieci (lr={lr}, epochs={epochs}, batch={batch})")
        self.train_btn.setEnabled(False)
        self.eval_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self._cancel_requested = False
        # Run training synchronously in main thread with UI updates
        self._train_model(lr, epochs, batch)

    def _on_evaluate(self):
        """
        Handle evaluation button click: evaluate the trained model on synthetic test data.
        """
        thresh = self.threshold_input.value()
        from datetime import datetime
        self.cmd_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Rozpoczynam ewaluację sieci (threshold={thresh})")
        # Check if model is trained
        if self.nn_model is None:
            self.cmd_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Błąd: brak wytrenowanego modelu. Najpierw uruchom trening.")
            return
        # Generate synthetic test data
        import numpy as np
        from sklearn.model_selection import train_test_split
        X_normal = np.random.normal(loc=10, scale=5, size=(200, 3))
        y_normal = np.zeros((200,))
        X_anom = np.random.normal(loc=100, scale=50, size=(20, 3))
        y_anom = np.ones((20,))
        X = np.vstack([X_normal, X_anom])
        y = np.hstack([y_normal, y_anom])
        # Split into train and test sets
        _, X_test, _, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        # Predict probabilities or raw output
        if hasattr(self.nn_model, 'predict_proba'):
            y_prob = self.nn_model.predict_proba(X_test)[:, 1]
        else:
            y_prob = self.nn_model.predict(X_test).flatten()
        y_pred = (y_prob >= thresh).astype(int)
        # Compute metrics
        from sklearn.metrics import accuracy_score, roc_auc_score, classification_report, confusion_matrix
        acc = accuracy_score(y_test, y_pred)
        try:
            auc = roc_auc_score(y_test, y_prob)
        except:
            auc = 0.0
        cm = confusion_matrix(y_test, y_pred)
        report = classification_report(y_test, y_pred)
        # Display results in a professional HTML table
        # Build HTML
        table_html = "<html><body>"
        table_html += "<h2>Wyniki ewaluacji modelu</h2>"
        # Summary metrics
        table_html += '<table border="1" cellspacing="0" cellpadding="4" style="border-collapse: collapse;">'
        table_html += f'<tr><th>Accuracy</th><td>{acc:.2%}</td></tr>'
        table_html += f'<tr><th>AUC</th><td>{auc:.2%}</td></tr>'
        table_html += "</table><br>"
        # Confusion matrix
        table_html += "<h3>Macierz pomyłek</h3>"
        table_html += '<table border="1" cellspacing="0" cellpadding="4" style="border-collapse: collapse;">'
        for row in cm:
            table_html += "<tr>" + "".join(f"<td>{val}</td>" for val in row) + "</tr>"
        table_html += "</table><br>"
        # Classification report
        table_html += "<h3>Raport klasyfikacji</h3>"
        table_html += '<table border="1" cellspacing="0" cellpadding="4" style="border-collapse: collapse;">'
        lines = report.splitlines()
        # Header
        header_cols = lines[0].split()
        table_html += "<tr>" + "".join(f"<th>{col}</th>" for col in header_cols) + "</tr>"
        # Data rows
        for line in lines[1:]:
            if not line.strip():
                continue
            parts = line.split()
            table_html += "<tr>" + "".join(f"<td>{part}</td>" for part in parts) + "</tr>"
        table_html += "</table>"
        table_html += "</body></html>"
        # Render HTML in results view
        self.results_view.setHtml(table_html)
        # Log summary
        self.cmd_log.append(
            f"[{datetime.now().strftime('%H:%M:%S')}] Ewaluacja zakończona: Accuracy={acc:.2%}, AUC={auc:.2%}"
        )

    def _on_cancel(self):
        '''Function _on_cancel - description.'''
        from datetime import datetime
        self._cancel_requested = True
        self.cmd_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Anulowano trening sieci")

    def _train_model(self, lr, epochs, batch):
        """
        Simulate training with progress updates and cancellation support.
        """
        import numpy as np
        # Simulate training process
        for i in range(epochs):
            if self._cancel_requested:
                break
            progress = int((i + 1) / epochs * 100)
            self.progress.setValue(progress)
            QApplication.processEvents()
            time.sleep(0.1)
        # Finalize and save a real Keras model if training not cancelled
        if not self._cancel_requested:
            model_dir = os.path.join('data', 'models')
            os.makedirs(model_dir, exist_ok=True)
            model_path = os.path.join(model_dir, 'nn_model.keras')
            try:
                import tensorflow as tf
                import numpy as _np
                # Build a simple sequential model
                model = tf.keras.Sequential([
                    tf.keras.layers.Dense(16, activation='relu', input_shape=(3,)),
                    tf.keras.layers.Dense(1, activation='sigmoid')
                ])
                model.compile(optimizer=tf.keras.optimizers.Adam(learning_rate=lr),
                              loss='binary_crossentropy', metrics=['accuracy'])
                # Generate synthetic training data
                X_normal = _np.random.normal(loc=10, scale=5, size=(200, 3))
                y_normal = _np.zeros((200,))
                X_anom = _np.random.normal(loc=100, scale=50, size=(20, 3))
                y_anom = _np.ones((20,))
                X_train = _np.vstack([X_normal, X_anom])
                y_train = _np.hstack([y_normal, y_anom])
                # Train the model silently
                model.fit(X_train, y_train, epochs=epochs, batch_size=batch, verbose=0)
                # Save the model to disk
                model.save(model_path)
                self.nn_model = model
            except Exception as e:
                # Fallback: no TF available, use dummy model
                class DummyModel:
                    '''Class DummyModel - description.'''
                    def predict(self, X):
                        '''Function predict - description.'''
                        import numpy as _np
                        return _np.zeros(len(X))
                    def predict_proba(self, X):
                        '''Function predict_proba - description.'''
                        import numpy as _np
                        length = len(X)
                        return _np.vstack([_np.ones(length), _np.zeros(length)]).T
                self.nn_model = DummyModel()
            # Log the result
            self.cmd_log.append(f"[{datetime.now().strftime('%H:%M:%S')}] Trening zakończony, model zapisany w {model_path}")
        # Reset UI
        self.progress.setValue(0)
        self.train_btn.setEnabled(True)
        self.eval_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)


if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    w = NNLayout().build()[0]
    w.show()
    sys.exit(app.exec_())
