import 'dotenv/config';
import cors from 'cors';
import express from 'express';
import routes from './routes';
import models, { sequelize } from './models';

const app = express();

// @TODO Implement CORS whitelisting!
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* Pass the models to all routes */
app.use((req, res, next) => {
  req.context = {
    models,
  };
  next();
});

app.use('/'+process.env.API_VERSION+'/group', routes.group);

/* Error handler */
app.use((err, req, res, next) => {
    res.status(err.status || 500)
	.json({
            message: err.message,
            error: {}
	});
});

/* Set to true for erasing DB upon Express restart (for testing) */
//const eraseDatabaseOnSync = true;
const eraseDatabaseOnSync = false;
sequelize.sync({ force: eraseDatabaseOnSync }).then(async () => {
  app.listen(process.env.PORT, () => {
    console.log(`Listening on port ${process.env.PORT}!`)
  });
});
