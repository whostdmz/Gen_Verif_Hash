import bcrypt
from argon2 import PasswordHasher, exceptions
import hashlib

def gen_hash(texte, algo):
    if algo == 'bcrypt':
        hashed = bcrypt.gensalt() # Permet de rajouter un sel permettant de renforcer le mdp avant le hashage
        return bcrypt.hashpw(texte.encode('utf-8'), hashed).decode('utf-8')
    elif algo == 'Argon2':
        ph = PasswordHasher()
        return ph.hash(texte)

def hash_file(file, size=65536):  #size = 64 Ko pour les partitions du fichiers
    sha512_hash = hashlib.sha512()
    with open(file, 'rb') as f:
        while True:
            partition = f.read(size)
            if not partition:
                break
            sha512_hash.update(partition)
    return sha512_hash.hexdigest()

from argon2 import PasswordHasher, exceptions
import bcrypt

def verif_hash(pwd, hsh):
    password_to_verify = pwd.encode('utf-8')
    # detecter le type de hash pour appeler la bonne méthode
    #---Argon2---
    if hsh.startswith("$argon2"):
        ph = PasswordHasher()
        try:
            if ph.verify(hsh, pwd):
                print("Mot de passe correct : Argon2 ")
                return True
        except exceptions.VerifyMismatchError:
            print("Mot de passe incorrect : Argon2 ")
            return False
        except exceptions.VerificationError:
            print("Erreur de vérification Argon2")
            return False
       #--- BCrypt --- 
    elif hsh.startswith("$2a$") or hsh.startswith("$2b$") or hsh.startswith("$2y$"):
        if bcrypt.checkpw(password_to_verify, hsh.encode('utf-8')):
            print("Mot de passe correct (bcrypt)")
            return True
        else:
            print("Mot de passe incorrect (bcrypt)")
            return False
    else:
        print("Algorithme de hash non reconnu")
        return False



