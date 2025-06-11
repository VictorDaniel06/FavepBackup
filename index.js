const express = require('express');
const app = express();
const cors = require('cors');
const authRoutes = require('./src/routes/routeAuth');
const propertyRoutes = require('./src/routes/routeProperty');
const productionsRoutes = require('./src/routes/routeProduction');
const financesRoutes = require('./src/routes/routeFinance');

app.use(cors());
app.use(express.json());

app.use('/auth', authRoutes);
app.use('/property', propertyRoutes);
app.use('/production', productionsRoutes);
app.use('/finance', financesRoutes);

app.get('/', (req, res) => {
  res.send('Servidor rodando com PostgreSQL!');
});

const PORT = process.env.PORT || 5050;
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
