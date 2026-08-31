"""
Entraine un classifieur TF-IDF + Regression Logistique sur data/dataset.csv
et sauvegarde le modele dans model.pkl.
Usage: python3 train_model.py
"""
import pandas as pd
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

df = pd.read_csv("data/dataset.csv")

X_train, X_test, y_train, y_test = train_test_split(
    df["text"], df["label"], test_size=0.2, random_state=42, stratify=df["label"]
)

vectorizer = TfidfVectorizer(lowercase=True, ngram_range=(1, 2), min_df=1)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec = vectorizer.transform(X_test)

model = LogisticRegression(max_iter=1000)
model.fit(X_train_vec, y_train)

print("=== Evaluation sur le jeu de test ===")
print(classification_report(y_test, model.predict(X_test_vec)))

with open("model.pkl", "wb") as f:
    pickle.dump({"model": model, "vectorizer": vectorizer}, f)

print("Modele sauvegarde dans model.pkl")
