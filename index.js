const express = require('express');
const session = require('express-session');
const methodOverride = require('method-override');
const dotenv = require('dotenv');
const pool = require('./database');

dotenv.config();

const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(methodOverride('_method'));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
app.set('view engine', 'ejs');

const routes = require('./routes'); 
app.use('/', routes);

app.listen(3000, () => console.log('Server running on port 3000'));