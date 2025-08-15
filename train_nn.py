import numpy as np
import os
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.optimizers import Adam

# Generowanie danych treningowych (przykładowe)
# cechy: packet_count, total_bytes, flow_id
X_normal = np.random.normal(loc=10, scale=5, size=(1000, 3))
y_normal = np.zeros((1000,))
X_anom = np.random.normal(loc=100, scale=50, size=(100, 3))
y_anom = np.ones((100,))

X = np.vstack([X_normal, X_anom])
y = np.hstack([y_normal, y_anom])

# Tasowanie
indices = np.random.permutation(len(X))
X = X[indices]
y = y[indices]

# Definicja modelu sieci neuronowej
model = Sequential([
    Dense(16, activation='relu', input_shape=(3,)),
    Dense(8, activation='relu'),
    Dense(1, activation='sigmoid'),
])
model.compile(optimizer=Adam(learning_rate=0.001), loss='binary_crossentropy', metrics=['accuracy'])

# Trening
model.fit(X, y, epochs=20, batch_size=32, validation_split=0.2)

# Zapis modelu w natywnym formacie Keras (.keras)
model_dir = os.path.join('data', 'models')
os.makedirs(model_dir, exist_ok=True)
model_path = os.path.join(model_dir, 'nn_model.keras')
model.save(model_path)
print(f"Model sieci neuronowej zapisany w natywnym formacie Keras: {model_path}")
