const express = require('express');
const path = require('path');
const db = require('./src/db/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();
const port = 3000;
const SECRET_KEY = 'sua_chave_secreta'; // Substitua por uma chave segura

// Middleware para processar JSON
app.use(express.json());

// Configurar arquivos estáticos
app.use(express.static(path.join(__dirname, 'src', 'public')));

// Middleware de autenticação
function autenticar(req, res, next) {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Token não fornecido' });
    
    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Token inválido' });
        req.usuarioId = decoded.id;
        req.usuarioRole = decoded.role; // Adiciona o papel ao request
        next();
    });
}

// Middleware para verificar se o usuário é admin
function isAdmin(req, res, next) {
    if (req.usuarioRole !== 'admin') {
        return res.status(403).json({ error: 'Acesso negado' });
    }
    next();
}

// Rota inicial (redireciona para o login ou dashboard)
app.get('/', (req, res) => {
    const token = req.headers['authorization'];
    if (token) {
        res.redirect('/dashboard.html');
    } else {
        res.redirect('/login.html');
    }
});

// Rota de Registro
app.post('/register', (req, res) => {
    const { nome, email, senha, role } = req.body;
    
    // Verificar se o email já está cadastrado
    db.get('SELECT * FROM usuarios WHERE email = ?', [email], (err, row) => {
        if (err) {
            console.error('Erro ao verificar email:', err);
            return res.status(500).json({ error: 'Erro interno do servidor' });
        }
        
        if (row) {
            return res.status(400).json({ error: 'Email já cadastrado' });
        }
        
        // Criptografar a senha
        bcrypt.hash(senha, 10)
            .then(hashedSenha => {
                // Inserir novo usuário
                const query = `INSERT INTO usuarios (nome, email, senha, role) VALUES (?, ?, ?, ?)`;
                db.run(query, [nome, email, hashedSenha, role || 'cliente'], function(err) {
                    if (err) {
                        console.error('Erro ao cadastrar usuário:', err);
                        return res.status(500).json({ error: 'Erro ao cadastrar usuário' });
                    }
                    res.json({ success: true, id: this.lastID });
                });
            })
            .catch(err => {
                console.error('Erro ao criptografar senha:', err);
                return res.status(500).json({ error: 'Erro ao processar registro' });
            });
    });
});

// Rota de Login
app.post('/login', (req, res) => {
    const { email, senha } = req.body;
    
    // Buscar usuário pelo email
    db.get('SELECT * FROM usuarios WHERE email = ?', [email], (err, row) => {
        if (err) {
            console.error('Erro ao buscar usuário:', err);
            return res.status(500).json({ error: 'Erro interno do servidor' });
        }
        
        if (!row) {
            return res.status(400).json({ error: 'Email ou senha incorretos' });
        }
        
        // Verificar senha
        bcrypt.compare(senha, row.senha)
            .then(senhaValida => {
                if (!senhaValida) {
                    return res.status(400).json({ error: 'Email ou senha incorretos' });
                }
                
                // Verificar se o campo role existe, se não, definir como 'cliente'
                const userRole = row.role || 'cliente';
                
                // Garantir que os dados sejam do tipo correto
                const userId = parseInt(row.id, 10) || 0;
                const userEmail = String(row.email || '');
                
                try {
                    // Gerar token JWT com o papel (role) - corrigido
                    const token = jwt.sign(
                        { 
                            id: userId, 
                            email: userEmail, 
                            role: userRole 
                        }, 
                        SECRET_KEY, 
                        { expiresIn: '1h' }
                    );
                    
                    res.json({ success: true, token });
                } catch (jwtError) {
                    console.error('Erro ao gerar token JWT:', jwtError);
                    return res.status(500).json({ error: 'Erro ao processar login' });
                }
            })
            .catch(err => {
                console.error('Erro ao verificar senha:', err);
                return res.status(500).json({ error: 'Erro ao processar login' });
            });
    });
});

// Rota para agendamento (protegida)
app.post('/agendar', autenticar, (req, res) => {
    const { nome, telefone, data, horario } = req.body;
    
    if (!nome || nome.length < 3) {
        return res.status(400).json({ error: 'Nome inválido' });
    }
    
    if (!telefone || telefone.length !== 11 || !/^\d+$/.test(telefone)) {
        return res.status(400).json({ error: 'Telefone inválido' });
    }
    
    if (!data || !horario) {
        return res.status(400).json({ error: 'Data ou horário inválidos' });
    }
    
    const query = `INSERT INTO agendamentos (cliente_nome, cliente_telefone, data, horario, usuario_id) VALUES (?, ?, ?, ?, ?)`;
    db.run(query, [nome, telefone, data, horario, req.usuarioId], function(err) {
        if (err) {
            console.error('Erro ao agendar:', err);
            return res.status(500).json({ error: 'Erro ao agendar' });
        }
        res.json({ success: true, id: this.lastID });
    });
});

// Rota para listar agendamentos (protegida)
app.get('/agendamentos', autenticar, (req, res) => {
    const usuarioId = req.usuarioId;
    
    db.all('SELECT * FROM agendamentos WHERE usuario_id = ?', [usuarioId], (err, rows) => {
        if (err) {
            console.error('Erro ao buscar agendamentos:', err);
            return res.status(500).json({ error: 'Erro ao buscar agendamentos' });
        }
        res.json(rows);
    });
});

// Rota para o Financeiro (só admin pode acessar)
app.get('/financeiro', autenticar, isAdmin, (req, res) => {
    // Lógica para buscar dados financeiros
    res.json({ success: true, data: 'Dados financeiros' });
});

// Iniciar o servidor
app.listen(port, () => {
    console.log(`Servidor rodando em http://localhost:${port}`);
});
