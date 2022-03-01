import * as https from "https"
import * as fs from "fs"
import * as express from 'express';

const SERVER_PORT = 8443; // SSL Port number

// singleton Server class
class Server {
  private server: https.Server;
  private app:    express.Application;
  private static  _instance: Server;

  constructor(sslOptions: https.ServerOptions) {
    this.app = express();
    this.router();
    this.server = https.createServer(sslOptions, this.app);
  }

  // Bootstrap the application
  public static start(): Server {
    const sslOptions: https.ServerOptions = process.env.NODE_ENV === 'production' ?
    {
      // Production configuration for SSL certificates
    } : {
      // Development configuration for SSL certificates
      key:  fs.readFileSync('./server_dev.key'),
      cert: fs.readFileSync('./server_dev.crt')
    }

    if (!this._instance)
      this._instance = new Server(sslOptions);

    // start SSL server
    this._instance.server.listen(SERVER_PORT, () => {
      console.log('Server listening on port ' + this._instance.server.address().Port);
    });

    return this._instance;
  }

  // Sample router
  private router() {
    this.app.get('/hello', (req, res) => { res.send('Hello World'); });
  }
}

// start server
Server.start();
