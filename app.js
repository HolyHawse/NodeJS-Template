const express = require('express');
const session = require('express-session');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const app = express();
const PORT = process.env.PORT || 4444;

const db = new sqlite3.Database('./data/sql.db');

app.set('views', path.join(__dirname, 'public', 'html'));
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: 'secret-key',
    resave: false,
    saveUninitialized: false
}));

function renderWithLayout(res, view, options = {}) {
    const layout = options.layout === false ? false : 'layout';
    if (layout) {
        require('ejs').renderFile(
            path.join(__dirname, 'public', 'html', view + '.ejs'),
            options,
            (err, str) => {
                if (err) return res.status(500).send('EJS render error: ' + err);
                res.render(layout, { ...options, body: str });
            }
        );
    } else {
        res.render(view, options);
    }
}

// Kullanıcı giriş kontrolü
function requireLogin(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    next();
}
// Admin kontrolü
function requireAdmin(req, res, next) {
    if (!req.session.user || !req.session.user.isAdmin) {
        return res.status(403).render('error', { user: req.session.user, error: 'Bu sayfaya erişim yetkiniz yok.', title: '403 - Yetkisiz Erişim', layout: false });
    }
    next();
}

// Ana sayfa
app.get('/', (req, res) => {
    renderWithLayout(res, 'main', { user: req.session.user, activePage: 'main', title: 'WebReport Ana Sayfa' });
});

// Login
app.get('/login', (req, res) => {
    if (req.session.user) return res.redirect('/');
    res.render('login', { layout: false, error: null, message: null });
});
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    db.get('SELECT id, username, password, name, surname, email, phone, tckimlikno, isAdmin FROM users WHERE username = ?', [username], (err, user) => {
        if (user && bcrypt.compareSync(password, user.password)) {
            req.session.user = user;
            res.redirect('/');
        } else {
            res.render('login', { layout: false, error: 'Hatalı giriş!', message: null });
        }
    });
});

// Register
app.post('/register', (req, res) => {
    const { username, password, name, surname, email, tckimlikno } = req.body;
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (user) {
            res.render('login', { layout: false, error: 'Kullanıcı adı mevcut!', message: null });
        } else {
            const hash = bcrypt.hashSync(password, 10);
            db.run('INSERT INTO users (username, password, name, surname, email, tckimlikno, isAdmin) VALUES (?, ?, ?, ?, ?, ?, 0)',
                [username, hash, name, surname, email, tckimlikno], function (err) {
                    if (err) return res.render('login', { layout: false, error: 'Kayıt hatası!', message: null });
                    res.render('login', { layout: false, error: null, message: 'Kayıt başarılı, giriş yapabilirsiniz.' });
                });
        }
    });
});

// Kullanıcılar (admin)
app.get('/users', requireAdmin, (req, res) => {
    db.all('SELECT * FROM users WHERE active = 1', [], (err, activeUsers) => {
        db.all('SELECT * FROM users WHERE active = 0', [], (err2, deletedUsers) => {
            activeUsers = (activeUsers || []).map(u => ({
                ...u,
                id: Number(u.id),
                isAdmin: Number(u.isAdmin)
            }));
            deletedUsers = (deletedUsers || []).map(u => ({
                ...u,
                id: Number(u.id),
                isAdmin: Number(u.isAdmin)
            }));
            renderWithLayout(res, 'users', {
                user: req.session.user,
                activeUsers,
                deletedUsers,
                activePage: 'users',
                title: 'Kullanıcılar'
            });
        });
    });
});

// Kullanıcı düzenle
app.post('/edit-user', requireAdmin, (req, res) => {
    const { id, name, surname, tckimlikno, email, phone, username, password, isAdmin } = req.body;
    db.get('SELECT id FROM users WHERE (username = ? OR tckimlikno = ?) AND id != ?', [username, tckimlikno, id], (err, row) => {
        if (row) {
            return res.redirect('/users?editError=Bu kullanıcı adı veya TC Kimlik No başka bir kullanıcıda mevcut!');
        }
        if (password && password.trim() !== '') {
            const hash = bcrypt.hashSync(password, 10);
            db.run('UPDATE users SET name=?, surname=?, tckimlikno=?, email=?, phone=?, username=?, password=?, isAdmin=? WHERE id=?',
                [name, surname, tckimlikno, email, phone, username, hash, isAdmin, id], function (err) {
                    res.redirect('/users');
                });
        } else {
            db.run('UPDATE users SET name=?, surname=?, tckimlikno=?, email=?, phone=?, username=?, isAdmin=? WHERE id=?',
                [name, surname, tckimlikno, email, phone, username, isAdmin, id], function (err) {
                    res.redirect('/users');
                });
        }
    });
});

// Kullanıcı sil
app.post('/delete-user', requireAdmin, (req, res) => {
    const { id } = req.body;
    db.run('UPDATE users SET active=0 WHERE id=?', [id], function (err) {
        res.redirect('/users');
    });
});

// Kullanıcı tekrar aktif et
app.post('/activate-user', requireAdmin, (req, res) => {
    const { id } = req.body;
    db.run('UPDATE users SET active=1 WHERE id=?', [id], function (err) {
        res.redirect('/users');
    });
});

// Profil
app.get('/profile', requireLogin, (req, res) => {
    db.get('SELECT id, username, name, surname, email, phone, tckimlikno, isAdmin FROM users WHERE id = ?', [req.session.user.id], (err, user) => {
        renderWithLayout(res, 'profile', { user, activePage: 'profile', title: 'Profilim' });
    });
});
app.post('/edit-profile', requireLogin, (req, res) => {
    const { id, name, surname, tckimlikno, email, phone, username, password } = req.body;
    db.get('SELECT id FROM users WHERE (username = ? OR tckimlikno = ?) AND id != ?', [username, tckimlikno, id], (err, row) => {
        if (row) {
            db.get('SELECT id, username, name, surname, email, phone, tckimlikno, isAdmin FROM users WHERE id = ?', [id], (err2, user) => {
                return renderWithLayout(res, 'profile', { user, activePage: 'profile', title: 'Profilim', editError: 'Bu kullanıcı adı veya TC Kimlik No başka bir kullanıcıda mevcut!' });
            });
            return;
        }
        if (password && password.trim() !== '') {
            const hash = bcrypt.hashSync(password, 10);
            db.run('UPDATE users SET name=?, surname=?, tckimlikno=?, email=?, phone=?, username=?, password=? WHERE id=?',
                [name, surname, tckimlikno, email, phone, username, hash, id], function (err) {
                    db.get('SELECT id, username, name, surname, email, phone, tckimlikno, isAdmin FROM users WHERE id = ?', [id], (err2, user) => {
                        req.session.user = user;
                        res.redirect('/profile');
                    });
                });
        } else {
            db.run('UPDATE users SET name=?, surname=?, tckimlikno=?, email=?, phone=?, username=? WHERE id=?',
                [name, surname, tckimlikno, email, phone, username, id], function (err) {
                    db.get('SELECT id, username, name, surname, email, phone, tckimlikno, isAdmin FROM users WHERE id = ?', [id], (err2, user) => {
                        req.session.user = user;
                        res.redirect('/profile');
                    });
                });
        }
    });
});

// İletişim
app.get('/contact', (req, res) => {
    db.all('SELECT * FROM contacts ORDER BY DATE DESC', [], (err, contacts) => {
        renderWithLayout(res, 'contact', { user: req.session.user, contacts, activePage: 'contact', title: 'İletişim' });
    });
});
app.post('/contact', (req, res) => {
    const { mail, message } = req.body;
    db.run('INSERT INTO contacts (MAIL, MESSAGE, DATE) VALUES (?, ?, datetime("now","localtime"))', [mail, message], (err) => {
        db.all('SELECT * FROM contacts ORDER BY DATE DESC', [], (err2, contacts) => {
            renderWithLayout(res, 'contact', {
                user: req.session.user,
                contacts,
                message: err ? 'Kayıt hatası!' : 'Mesajınız kaydedildi.',
                activePage: 'contact',
                title: 'İletişim'
            });
        });
    });
});
app.post('/delete-contact', requireAdmin, (req, res) => {
    const { id } = req.body;
    db.run('DELETE FROM contacts WHERE id = ?', [id], function (err) {
        res.redirect('/dashboard');
    });
});

// Dashboard (admin, iletişim mesajları)
app.get('/dashboard', requireAdmin, (req, res) => {
    const pageSize = 12;
    const pageNo = Number(req.query.ContactPage) || 1;
    db.all('SELECT COUNT(*) as total FROM contacts', [], (err, countRows) => {
        const totalContacts = countRows[0].total;
        const contactsTotalPages = Math.ceil(totalContacts / pageSize);
        db.all('SELECT * FROM contacts ORDER BY DATE DESC LIMIT ? OFFSET ?', [pageSize, (pageNo - 1) * pageSize], (err2, contactsPage) => {
            renderWithLayout(res, 'dashboard', {
                user: req.session.user,
                contactsPage,
                contactsTotalPages,
                ContactPageNo: pageNo,
                activePage: 'dashboard',
                title: 'Dashboard'
            });
        });
    });
});

// SQL (admin)
app.get('/sql', requireAdmin, (req, res) => {
    renderWithLayout(res, 'sql', { user: req.session.user, activePage: 'sql', title: 'SQL' });
});
app.post('/sql', requireAdmin, (req, res) => {
    const query = req.body.query;
    db.all(query, [], (err, rows) => {
        renderWithLayout(res, 'sql', {
            user: req.session.user,
            query,
            result: err ? undefined : rows,
            error: err ? err.message : undefined,
            activePage: 'sql',
            title: 'SQL'
        });
    });
});

// Hakkında
app.get('/information', (req, res) => {
    renderWithLayout(res, 'information', { user: req.session.user, activePage: 'information', title: 'Hakkında' });
});

// Çıkış
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        res.redirect('/');
    });
});

// Error (layout kullanılmaz)
app.get('/error', (req, res) => {
    res.render('error', { layout: false });
});

app.listen(PORT, () => {
    console.log(`WebReport çalışıyor: http://localhost:${PORT}`);
});