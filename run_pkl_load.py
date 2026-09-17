import xgboost as xgb
import sklearn
import pickle
import spacy
import __main__
import sys

print(f'XGBoost local: {xgb.__version__}')
print(f'Scikit-learn local: {sklearn.__version__}')

nlp = spacy.load('es_core_news_sm')

def lematizador_spacy(texto):
    doc = nlp(texto)
    return [token.lemma_.lower() for token in doc if not token.is_punct and not token.is_space]

__main__.lematizador_spacy = lematizador_spacy

path = r'C:\Users\gabri\Downloads\Clasificador_NLP\Clasificador NLP\phisharg_modelo_xgboost_hardcore.pkl'
try:
    with open(path, 'rb') as f:
        data = pickle.load(f)
    print('Hardcore PKL loaded OK!')
    print(f'Keys: {list(data.keys())}')
    print(f'Umbral: {data.get("umbral_critico")}')
except Exception as e:
    print(f'Error: {type(e).__name__}: {e}')
    sys.exit(1)
