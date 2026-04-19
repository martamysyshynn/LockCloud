import json, os

_cache = {}

def load_lang(lang):
    if lang not in _cache:
        path = os.path.join('translations', f'{lang}.json')
        with open(path, encoding='utf-8') as f:
            _cache[lang] = json.load(f)
    return _cache[lang]

def get_text(key, lang='en'):
    return load_lang(lang).get(key, key)