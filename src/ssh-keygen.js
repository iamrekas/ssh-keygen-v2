var spawn = require("child_process").spawn;
var _ = require("underscore");
var fs = require("fs");
var os = require("os");
var path = require("path");
var request = require('request');

var log = function(a) {
  if (process.env.VERBOSE) console.log("ssh-keygen: " + a);
};

async function downloadTempBin() {
  if (process.platform !== "win32") throw new Error("Unsupported platform");
  var file;
  var fileToDownload;
	switch(process.arch) {
		case 'ia32':  {
      fileToDownload = 'https://github.com/iamrekas/ssh-keygen-v2/raw/master/bin/ssh-keygen-32.exe';
      file = fs.createWriteStream(path.join(os.tmpdir(), 'tmp-ssh-keygen-32.exe'));
      break;
    }
		case 'x64': {
      fileToDownload = 'https://github.com/iamrekas/ssh-keygen-v2/raw/master/bin/ssh-keygen-64.exe';
      file = fs.createWriteStream(path.join(os.tmpdir(), 'tmp-ssh-keygen-64.exe'));
      break;
    }
	}

  await new Promise(function (resolve, reject) {
    let stream = request({
        /* Here you should specify the exact link to the file you are trying to download */
        uri: fileToDownload,
        headers: {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'Accept-Language': 'lt,en-US;q=0.9,en;q=0.8,ru;q=0.7,pl;q=0.6',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.97 Safari/537.36'
        },
        /* GZIP true for most of the websites now, disable it if you don't need it */
        gzip: false
    })
    .pipe(file)
    .on('finish', function () {
        resolve();
    })
    .on('error', function (error) {
        reject(error);
    })
  })

  return file;
}

function binPath() {
  if (process.platform !== "win32") return "ssh-keygen";

	switch(process.arch) {
		case 'ia32': return path.join(__dirname, '..', 'bin', 'ssh-keygen-32.exe');
		case 'x64': return path.join(__dirname, '..', 'bin', 'ssh-keygen-64.exe');
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
function ssh_keygen(location, opts, callback) {
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
  if (!fs.existsSync(binLocation)) {
    binLocation = downloadTempBin();
    var oldCallback = callback;
    callback = function(errro, data) {
      fs.unlinkSync(binLocation);
      oldCallback(errro, data);
    }
  }

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
