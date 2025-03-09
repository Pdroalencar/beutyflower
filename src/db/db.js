const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.db');

// Habilitar modo WAL para evitar bloqueios
db.run('PRAGMA journal_mode=WAL;');

// Criar tabelas
db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            senha TEXT NOT NULL,
            role TEXT DEFAULT 'cliente'
        )
    `);

    // Tenta adicionar a coluna 'role' se ela ainda não existir
    db.run(`
        ALTER TABLE usuarios ADD COLUMN role TEXT DEFAULT 'cliente'
    `, (err) => {
        if (err && !err.message.includes('duplicate column')) {
            console.error('Erro ao adicionar coluna role:', err);
        }
    });

    db.run(`
        CREATE TABLE IF NOT EXISTS agendamentos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cliente_nome TEXT,
            cliente_telefone TEXT,
            data TEXT,
            horario TEXT,
            usuario_id INTEGER
        )
    `);
});

module.exports = db;
