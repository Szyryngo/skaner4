"""Module nn_layout: provides a PyQt5 tab for configuring, training, and evaluating a neural network using TensorFlow or sklearn.

This module implements the NNLayout class which builds UI controls for hyperparameters, handles model training in a background thread,
and presents evaluation metrics in a formatted HTML table."""
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QSpinBox, QDoubleSpinBox, QPushButton,
    QTextEdit, QHBoxLayout, QGroupBox, QApplication
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QTextCursor
import threading
import numpy as np
import os

# Register QTextCursor for queued signal connections in NNLayout
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
            Dictionary of UI controls keyed by name: 'train_btn', 'eval_btn', 'lr_input', etc.
        """
        widget = QWidget()
        layout = QVBoxLayout(widget)
        # Initialize model attribute
        self.nn_model = None

        # Grupa parametrów sieci
        from PyQt5.QtWidgets import QGroupBox, QLabel, QDoubleSpinBox, QSpinBox
        params_group = QGroupBox("Parametry sieci NN")
        params_layout = QVBoxLayout()
        # Skrótowy opis parametrów
        desc_label = QLabel(
            "Learning rate: szybkość uczenia; Epochs: liczba przebiegów; Batch size: wielkość partii; Threshold: próg decyzyjny"
        )
        desc_label.setStyleSheet("font-style: italic; font-size: 10px;")
        params_layout.addWidget(desc_label)
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
        from PyQt5.QtWidgets import QPushButton, QHBoxLayout
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
        # Połączenia: sygnały trenowania/oceny podłączone w MainWindow
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
        """
        Handle training button click: start training in a background thread.

        Reads hyperparameters from inputs, logs start message, and launches `_train_model`.
        """
        lr = self.lr_input.value()
        epochs = self.epochs_input.value()
        batch = self.batch_input.value()
        self.results_view.append(f"Rozpoczynam trening: lr={lr}, epochs={epochs}, batch={batch}")
        # TODO: uruchom rzeczywisty trening w tle
        threading.Thread(target=self._train_model, args=(lr, epochs, batch), daemon=True).start()

    def _train_model(self, lr, epochs, batch):
        """
        Train the neural network or sklearn MLPClassifier with given hyperparameters.

        Parameters
        ----------
        lr : float
            Learning rate for optimizer or initial learning rate for MLPClassifier.
        epochs : int
            Number of epochs (iterations) for training.
        batch : int
            Batch size for model training.

        Notes
        -----
        Uses TensorFlow/Keras if available; otherwise falls back to sklearn.neural_network.MLPClassifier.
        Training progress is appended to `results_view` via Qt signals.
        """
        # Dynamiczne importy TensorFlow i sklearn
        use_tf = True
        try:
            import tensorflow as tf
            keras_models = tf.keras.models
            keras_layers = tf.keras.layers
            keras_optim = tf.keras.optimizers
        except ImportError:
            use_tf = False
            self.results_view.append("TensorFlow nie jest zainstalowany, używam sklearn MLPClassifier.")
        from sklearn.model_selection import train_test_split
    # Generowanie przykładowych danych (symulacja flow)
        X_normal = np.random.normal(loc=10, scale=5, size=(1000, 3))
        y_normal = np.zeros((1000,))
        X_anom = np.random.normal(loc=100, scale=50, size=(100, 3))
        y_anom = np.ones((100,))
        X = np.vstack([X_normal, X_anom])
        y = np.hstack([y_normal, y_anom])
        # Podział na zbiór trening+walidacja i test
        X_train, X_temp, y_train, y_temp = train_test_split(X, y, test_size=0.2, random_state=42)
        X_val, X_test, y_val, y_test = train_test_split(X_temp, y_temp, test_size=0.5, random_state=42)
        # Trening modelu
        if use_tf:
            # Build Keras model
            model = keras_models.Sequential([
                keras_layers.Dense(16, activation='relu', input_shape=(3,)),
                keras_layers.Dense(8, activation='relu'),
                keras_layers.Dense(1, activation='sigmoid'),
            ])
            model.compile(optimizer=keras_optim.Adam(learning_rate=lr), loss='binary_crossentropy', metrics=['accuracy'])
            history = model.fit(
                X_train, y_train,
                epochs=epochs,
                batch_size=batch,
                validation_data=(X_val, y_val),
                verbose=0,
                callbacks=[
                    tf.keras.callbacks.LambdaCallback(
                        on_epoch_end=lambda epoch, logs: self.results_view.append(
                            f"Epoka {epoch+1}/{epochs}: loss={logs['loss']:.4f}, val_loss={logs['val_loss']:.4f}, "
                            f"acc={logs['accuracy']:.4f}, val_acc={logs['val_accuracy']:.4f}"
                        )
                    )
                ]
            )
            self.nn_model = model
        else:
            # Fallback: use sklearn MLPClassifier
            from sklearn.neural_network import MLPClassifier
            # Ensure valid learning rate
            if lr <= 0.0:
                lr = 0.001
            clf = MLPClassifier(hidden_layer_sizes=(16,8), learning_rate_init=lr, max_iter=epochs, batch_size=batch)
            clf.fit(X_train, y_train)
            self.nn_model = clf
            self.results_view.append("Trening MLPClassifier zakończony.")
        # Zapis modelu
        model_dir = os.path.join('data', 'models')
        os.makedirs(model_dir, exist_ok=True)
        model_path = os.path.join(model_dir, 'nn_model.keras')
        model.save(model_path)
        self.results_view.append(f"Trening zakończony, model zapisany w {model_path}")

    def _on_evaluate(self):
        """
        Handle evaluation button click: evaluate the trained model on synthetic test data.

        Computes accuracy, AUC, confusion matrix, classification report, and a human-readable summary,
        then displays them in `results_view` as an HTML formatted table.
        """
        thresh = self.threshold_input.value()
        # Import sklearn metrics
        from sklearn.metrics import accuracy_score, roc_auc_score, classification_report, confusion_matrix
        # Load model if not in memory
        if self.nn_model is None:
            try:
                import tensorflow as tf
                keras_models = tf.keras.models
                model_path = os.path.join('data', 'models', 'nn_model.keras')
                self.nn_model = keras_models.load_model(model_path)
                self.results_view.append(f"Załadowano model Keras z {model_path}")
            except Exception:
                self.results_view.append("Brak modelu w pamięci ani pliku. Najpierw uruchom trening.")
                return
        # Generate test data
        X_normal = np.random.normal(loc=10, scale=5, size=(200, 3))
        y_normal = np.zeros((200,))
        X_anom = np.random.normal(loc=100, scale=50, size=(20, 3))
        y_anom = np.ones((20,))
        X_test = np.vstack([X_normal, X_anom])
        y_test = np.hstack([y_normal, y_anom])
        # Predictions: sklearn or Keras
        if hasattr(self.nn_model, 'predict_proba'):
            # sklearn model
            y_prob = self.nn_model.predict_proba(X_test)[:, 1]
            y_pred = self.nn_model.predict(X_test)
        else:
            # Keras model
            y_prob = self.nn_model.predict(X_test).flatten()
            y_pred = (y_prob >= thresh).astype(int)
        # Compute metrics
        from sklearn.metrics import precision_score, recall_score, f1_score
        acc = accuracy_score(y_test, y_pred)
        auc = roc_auc_score(y_test, y_prob)
        report = classification_report(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)
        # Calculate per-class scores for summary
        prec0 = precision_score(y_test, y_pred, pos_label=0)
        rec0 = recall_score(y_test, y_pred, pos_label=0)
        f1_0 = f1_score(y_test, y_pred, pos_label=0)
        prec1 = precision_score(y_test, y_pred, pos_label=1)
        rec1 = recall_score(y_test, y_pred, pos_label=1)
        f1_1 = f1_score(y_test, y_pred, pos_label=1)
        # Display results in an HTML table
        self.results_view.clear()
        html = f"<h4>Metryki na zbiorze testowym (threshold={thresh})</h4>"
        html += "<table border='1' cellspacing='0' cellpadding='4'>"
        html += "<tr><th>Accuracy</th><th>AUC</th></tr>"
        html += f"<tr><td>{acc:.4f}</td><td>{auc:.4f}</td></tr>"
        html += "</table>"
        # Confusion matrix
        html += "<h4>Confusion Matrix</h4>"
        html += "<table border='1' cellspacing='0' cellpadding='4'>"
        html += "<tr><th></th><th>Pred 0</th><th>Pred 1</th></tr>"
        html += f"<tr><th>True 0</th><td>{cm[0,0]}</td><td>{cm[0,1]}</td></tr>"
        html += f"<tr><th>True 1</th><td>{cm[1,0]}</td><td>{cm[1,1]}</td></tr>"
        html += "</table>"
        # Classification report
        html += "<h4>Classification Report</h4>"
        html += "<pre>" + report + "</pre>"
        # Human-readable summary
        summary = (
            f"Dokładność modelu: {acc:.2%}, AUC: {auc:.2%}. "
            f"Klasa 0 – precyzja {prec0:.2%}, czułość {rec0:.2%}, F1 {f1_0:.2%}. "
            f"Klasa 1 – precyzja {prec1:.2%}, czułość {rec1:.2%}, F1 {f1_1:.2%}."
        )
        html += f"<h4>Podsumowanie</h4><p>{summary}</p>"
        self.results_view.setHtml(html)

# Test uruchomienia zakładki samodzielnie
if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    w = NNLayout().build()[0]
    w.show()
    sys.exit(app.exec_())
