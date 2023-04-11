require('dotenv').config();
require('express-async-errors');

// packages for extra security

const helmet = require('helmet')
const cors = require('cors')
const xss = require('xss-clean')
const rateLimiter = require('express-rate-limit')

// Swagger

const swaggerUI = require('swagger-ui-express')
const YAML = require('yamljs')

const swaggerDocument = YAML.load('./swagger.yaml')



const express = require('express');
const app = express();

//connectDB
const connectDB = require('./db/connect')

const authenticateUser = require('./middleware/authentication')

//routers
const authRouter = require('./routes/auth')
const jobsRouter = require('./routes/jobs')


// error handler
const notFoundMiddleware = require('./middleware/not-found');
const errorHandlerMiddleware = require('./middleware/error-handler');


// If your app is going to use reverse proxy, use this
app.set('trust proxy',1)


app.use(rateLimiter({
    windowMs: 20 * 60 * 1000, // 15 minutes
    max: 100, // li

}))
app.use(express.json());
app.use(helmet())
app.use(cors())
app.use(xss())

// extra packages

app.get('/',(req,res) => {
    res.send('<h1>This is the JOB LISTER api</h1> <a href="/api-docs">API Documentation</a>')
})

app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerDocument))

// routes
app.use('/api/v1/auth', authRouter)
app.use('/api/v1/jobs', authenticateUser, jobsRouter)

app.use(notFoundMiddleware);
app.use(errorHandlerMiddleware);

const port = process.env.PORT || 3000;

const start = async () => {
  try {
    await connectDB(process.env.MONGO_URI)
    app.listen(port, () =>
      console.log(`Server is listening on port ${port}...`)
    );
  } catch (error) {
    console.log(error);
  }
};

start();
