var spawn = require("child_process").spawn;
var _ = require("underscore");
var fs = require("fs");
var os = require("os");
var path = require("path");
var request = require('request');
var tmp = require('tmp');
var extract = require('extract-zip');

var tmpobj;

var log = function(a) {
  if (process.env.VERBOSE) console.log("ssh-keygen: " + a);
};

async function downloadTempBin() {
  if (process.platform !== "win32") throw new Error("Unsupported platform");
  var fileName;
  var fileZip;
  var fileToDownload;

  tmpobj = tmp.dirSync({ unsafeCleanup: true });

	switch(process.arch) {
		case 'ia32':  {
      fileToDownload = 'https://github.com/iamrekas/ssh-keygen-v2/raw/master/bin/32.zip';
      fileName = path.join(tmpobj.name, 'ssh-keygen.exe');
      fileZip = path.join(tmpobj.name, '32.zip');
      break;
    }
		case 'x64': {
      fileToDownload = 'https://github.com/iamrekas/ssh-keygen-v2/raw/master/bin/64.zip';
      fileName = path.join(tmpobj.name, 'ssh-keygen.exe');
      fileZip = path.join(tmpobj.name, '64.zip');
      break;
    }
	}

  function download(url) {
    return new Promise(function (resolve, reject){ 
      const file = fs.createWriteStream(fileZip);
      const sendReq = request.get(url);

      // verify response code
      sendReq.on('response', (response) => {
          if (response.statusCode !== 200) {
              return reject('Response status was ' + response.statusCode);
          }

          sendReq.pipe(file);
      });

      // close() is async, call cb after close completes
      file.on('finish', function (){ 
        file.close(async function () {
          try {
            await extract(fileZip, { dir: tmpobj.name });
            resolve();
          }catch(err) {
            reject(err);
          }
        });
      });

      // check for request errors
      sendReq.on('error', (err) => {
          fs.unlink(dest);
          return reject(err.message);
      });

      file.on('error', (err) => { // Handle errors
          fs.unlink(dest); // Delete the file async. (But we don't check the result)
          return reject(err.message);
      });
    });
  }

  await download(fileToDownload);

  return fileName;
}

function binPath() {
  if (process.platform !== "win32") return "ssh-keygen";

	switch(process.arch) {
		case 'ia32': return path.join(__dirname, '..', 'bin', '32', 'ssh-keygen.exe');
		case 'x64': return path.join(__dirname, '..', 'bin', '64', 'ssh-keygen.exe');
	}

  throw new Error("Unsupported platform");
}
function checkAvailability(location, force, callback) {
  var pubLocation = location + ".pub";
  log("checking availability: " + location);
  fs.exists(location, function(keyExists) {
    log("checking availability: " + pubLocation);
    fs.exists(pubLocation, function(pubKeyExists) {
      doForce(keyExists, pubKeyExists);
    });
  });
  function doForce(keyExists, pubKeyExists) {
    if (!force && keyExists) return callback(location + " already exists");
    if (!force && pubKeyExists)
      return callback(pubLocation + " already exists");
    if (!keyExists && !pubKeyExists) return callback();
    if (keyExists) {
      log("removing " + location);
      fs.unlink(location, function(err) {
        if (err) return callback(err);
        keyExists = false;
        if (!keyExists && !pubKeyExists) callback();
      });
    }
    if (pubKeyExists) {
      log("removing " + pubLocation);
      fs.unlink(pubLocation, function(err) {
        if (err) return callback(err);
        pubKeyExists = false;
        if (!keyExists && !pubKeyExists) callback();
      });
    }
  }
}
async function ssh_keygen(location, opts, callback) {
  opts || (opts = {});

  var pubLocation = location + ".pub";
  if (!opts.comment) opts.comment = "";
  if (!opts.password) opts.password = "";
  if (!opts.encryption) opts.encryption = "rsa";
  if (!opts.size) {
    switch (opts.encryption) {
      case "rsa":
        opts.size = "2048";
        break;
      case "dsa":
        opts.size = "1024";
        break;
      case "ecdsa":
        opts.size = "256";
        break;
      case "ed25519":
        opts.size = "256";
        break;
      default:
        opts.size = "2048";
        opts.encryption = "rsa";
    }
  } else {
    switch (opts.encryption) {
      case "rsa":
        if (!(["1024", "2048"].indexOf(opts.size) >= 0)) opts.size = "2048";
        break;
      case "dsa":
        if (!(["1024"].indexOf(opts.size) >= 0)) opts.size = "1024";
        break;
      case "ecdsa":
        if (!(["256", "384", "521"].indexOf(opts.size) >= 0)) opts.size = "521";
        break;
      case "ed25519":
        if (!(["256"].indexOf(opts.size) >= 0)) opts.size = "256";
        break;
      default:
        opts.size = "2048";
        opts.encryption = "rsa";
    }
  }

  var binLocation = binPath();
  // if (!fs.existsSync(binLocation)) {
    binLocation = await downloadTempBin();
    callback = (function(orgCallback) {
      return function(errro, data) {
        if (tmpobj) tmpobj.removeCallback();
        // fs.unlinkSync(binLocation);
        orgCallback(errro, data);
      }
    })(callback);
  // }
  var keygen = spawn(binLocation, [
    "-t",
    opts.encryption,
    "-b",
    opts.size,
    "-C",
    opts.comment,
    "-N",
    opts.password,
    "-f",
    location
  ]);

  keygen.stdout.on("data", function(a) {
    log("stdout:" + a);
  });

  var read = opts.read;
  var destroy = opts.destroy;

  keygen.on("exit", function() {
    log("exited");
    if (read) {
      log("reading key " + location);
      fs.readFile(location, "utf8", function(err, key) {
        if (destroy) {
          log("destroying key " + location);
          fs.unlink(location, function(err) {
            if (err) return callback(err);
            readPubKey();
          });
        } else readPubKey();
        function readPubKey() {
          log("reading pub key " + pubLocation);
          fs.readFile(pubLocation, "utf8", function(err, pubKey) {
            if (destroy) {
              log("destroying pub key " + pubLocation);
              fs.unlink(pubLocation, function(err) {
                if (err) return callback(err);
                key = key.toString();
                key = key.substring(0, key.lastIndexOf("\n")).trim();
                pubKey = pubKey.toString();
                pubKey = pubKey.substring(0, pubKey.lastIndexOf("\n")).trim();
                return callback(undefined, {
                  key: key,
                  pubKey: pubKey
                });
              });
            } else callback(undefined, { key: key, pubKey: pubKey });
          });
        }
      });
    } else if (callback) callback();
  });

  keygen.stderr.on("data", function(a) {
    log("stderr:" + a);
  });
}

module.exports = function(opts, callback) {
  var location = opts.location;
  if (!location) location = path.join(os.tmpdir(), "id_rsa");

  if (_.isUndefined(opts.read)) opts.read = true;
  if (_.isUndefined(opts.force)) opts.force = true;
  if (_.isUndefined(opts.destroy)) opts.destroy = false;

  checkAvailability(location, opts.force, function(err) {
    if (err) {
      log("availability err " + err);
      return callback(err);
    }
    ssh_keygen(location, opts, callback);
  });
};
