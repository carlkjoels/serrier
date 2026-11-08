import os


def hamta_nyckel():
    return os.environ["API_KEY"]   # placeholder/env-ref — ska EJ flaggas (sant negativt)


def berakna(uttryck):
    return eval(uttryck)           # osäker: eval på godtycklig indata (semgrep-träff)
