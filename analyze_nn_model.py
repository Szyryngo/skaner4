"""
Skrypt do analizy wytrenowanego modelu sieci neuronowej.
Ładuje model z data/models/nn_model.keras i wypisuje podsumowanie architektury.
Uruchom:
    python analyze_nn_model.py
"""

import tensorflow as tf

# Ścieżka do wytrenowanego modelu
model_path = 'data/models/nn_model.keras'

# Ładowanie modelu
model = tf.keras.models.load_model(model_path)

# Wypisanie podsumowania architektury
print("Podsumowanie modelu sieci neuronowej:")
model.summary()

# Możesz również wypisać szczegółowe kształty wag dla każdej warstwy:
print("\nSzczegóły wag każdej warstwy:")
for layer in model.layers:
    weights = layer.get_weights()
    if weights:
        print(f"Warstwa: {layer.name}")
        for i, w in enumerate(weights):
            print(f"  Waga[{i}] shape: {w.shape}")
        print()
