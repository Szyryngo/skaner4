"""
Skrypt do analizy wytrenowanego modelu sieci neuronowej.
Ładuje model z data/models/nn_model.keras i wypisuje podsumowanie architektury.
Uruchom:
    python analyze_nn_model.py
"""
import tensorflow as tf
model_path = 'data/models/nn_model.keras'
model = tf.keras.models.load_model(model_path)
print('Podsumowanie modelu sieci neuronowej:')
model.summary()
print("""
Szczegóły wag każdej warstwy:""")
for layer in model.layers:
    weights = layer.get_weights()
    if weights:
        print(f'Warstwa: {layer.name}')
        for i, w in enumerate(weights):
            print(f'  Waga[{i}] shape: {w.shape}')
        print()
