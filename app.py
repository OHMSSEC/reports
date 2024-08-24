from fastapi import FastAPI
from flask import jsonify
import sqlite3
import time

app = FastAPI()

@app.get("/")
# Função para conectar ao banco de dados e executar consultas
def query_db(query, args=(), one=False):
    con = sqlite3.connect(U"C:\\Users\\ohmsl\\Downloads\\database\\database.sqlite")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    start_time = time.time()  # Início do tempo de execução
    cur.execute(query, args)
    rv = cur.fetchall()
    end_time = time.time()  # Fim do tempo de execução
    con.close()
    print(f"Query execution time: {end_time - start_time} seconds")  # Log do tempo de execução
    return (rv[0] if rv else None) if one else rv

# Rota para obter os 10 registros mais recentes
@app.get('/api/users')
def get_users():
    users = query_db('SELECT * FROM datasus DESC LIMIT 10;')
    users_list = [dict(user) for user in users]
    return jsonify(users_list)

# Rota para obter um usuário específico por CPF (API)
@app.get('/api/user/cpf/<string:user_cpf>')
def get_user(user_cpf):
    user = query_db('SELECT * FROM datasus WHERE cpf = ? LIMIT 10' , [user_cpf], one=True)
    if user:
        return jsonify(dict(user))
    else:
        return jsonify({'error': 'User not found'}), 404

# Rota para exibir dados de um usuário específico por telefone (Página HTML)
@app.get('/api/user/telefone/<string:user_telefone>')
def user_page(user_telefone):
    print(f"Received telefone: {user_telefone}")  #Naõ funciona em 1 linha!
    user = query_db("""
    SELECT *
    FROM datasus
    WHERE telefone = ?
    LIMIT 1;
    """, [user_telefone], one=True)
    print(f"Query result: {user}")  # Debugging
    if user:
        return jsonify(dict(user))
    else:
        return jsonify({'error': 'User not found'}), 404

    
