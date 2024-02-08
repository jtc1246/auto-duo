function arrayBufferToBase64(buffer) {
  let binary = "";
  let bytes = new Uint8Array(buffer);
  let len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function twoDigits(input) {
  return input.toString().padStart(2, '0');
}

function base64ToArrayBuffer(base64) {
  var binary_string = window.atob(base64);
  var len = binary_string.length;
  var bytes = new Uint8Array(len);
  for (var i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
  }
  return bytes.buffer;
}

var di = {};
console.log("auto_duo.js loaded");

// 用于通过二维码获取密钥
async function activateDevice(rawCode) {
  // Split activation code into its two components: identifier and host.
  let code = rawCode.split('-');
  // Decode Base64 to get host
  let host = atob(code[1]);
  let identifier = code[0];
  // Ensure this code is correct by counting the characters
  if(code[0].length != 20 || code[1].length != 38) {
    throw "Illegal number of characters in activation code";
  }

  let url = 'https://' + host + '/push/v2/activation/' + identifier;
  // Create new pair of RSA keys
  let keyPair = await window.crypto.subtle.generateKey({
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: "SHA-512"
  }, true, ["sign", "verify"]);

  // Convert public key to PEM format to send to Duo
  let pemFormat = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
  pemFormat = window.btoa(String.fromCharCode(...new Uint8Array(pemFormat))).match(/.{1,64}/g).join('\n');
  pemFormat = `-----BEGIN PUBLIC KEY-----\n${pemFormat}\n-----END PUBLIC KEY-----`;

  // Exporting keys returns an array buffer. Convert it to Base64 string for storing
  let publicRaw = arrayBufferToBase64(await window.crypto.subtle.exportKey("spki", keyPair.publicKey));
  let privateRaw = arrayBufferToBase64(await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey));

  // Initialize new HTTP request
  let request = new XMLHttpRequest();
  let error = false;
  console.log(url)
  request.open('POST', url, true);
  request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  // Put onload() in a Promise. It will be raced with a timeout promise
  let newData = new Promise((resolve, reject) => {
    request.onload = async function () {
      let result = JSON.parse(request.responseText);
      // If successful
      if (result.stat == "OK") {
        // Get device info as JSON
        // 这是 密钥的信息
        let deviceInfo = {
          "akey": result.response.akey,
          "pkey": result.response.pkey,
          "host": host,
          // Encode keys to Base64 for JSON serializing
          "publicRaw": publicRaw,
          "privateRaw": privateRaw
        };
        // Store device info in chrome sync
        // 保存数据，之后要切换成其它方式输出
        // await chrome.storage.sync.set({"deviceInfo": deviceInfo});
        di = deviceInfo;
        resolve("Success");
      }
      else {
        // If we receive a result from Duo and the status is FAIL, the activation code is likely expired
        console.error(result);
        reject("Expired");
      }
    };
  });
  // await new Promise(resolve => setTimeout(resolve, 2000));
  // Append URL parameters and begin request
  // 这里的 request 是前面定义的对象，不是新建一个请求
  console.log(encodeURIComponent(pemFormat))
  request.send("?customer_protocol=1&pubkey=" + encodeURIComponent(pemFormat) + "&pkpush=rsa-sha512&jailbroken=false&architecture=arm64&region=US&app_id=com.duosecurity.duomobile&full_disk_encryption=true&passcode_status=true&platform=Android&app_version=3.49.0&app_build_number=323001&version=11&manufacturer=unknown&language=en&model=Browser%20Extension&security_patch_level=2021-02-01");
  // Create timeout promise
  let timeout = new Promise((resolve, reject) => {
    setTimeout(() => {
      reject("Timed out");
    }, 1500);
  });
  // Wait for response, or timeout at 1.5s
  // We need a timeout because request.send() doesn't return an error when an exception occurs, and onload() is obviously never called
  await Promise.race([newData, timeout]);
}

// 点击 push 按钮之后自动同意的函数
async function agree_push () {
  // loading = true;
  // Disable button while making Duo request
  // pushButton.disabled = true;
  // pushButton.innerText = "Working...";
  // let root = "Checking for Duo logins";
  // let dots = 0;
  // splash.innerHTML = `${root}...`;
  // Show loading ...
  // let loadingInterval = setInterval(() => {
  //   splash.innerText = `${root}${'.'.repeat(dots + 1)}`;
  //   dots = (dots + 1) % 3;
  // }, 300);
  try {
    // Get device info from storage
    // 这里 读取之前储存的数据，接下来要换成其它方式输入
    // let info = await getDeviceInfo();
    let info = di;
    let transactions = (await buildRequest(info, "GET", "/push/v2/device/transactions")).response.transactions;
    // If no transactions exist at the moment
    if(transactions.length == 0) {
      // failedAttempts++;
      // splash.innerHTML = "No logins found!";
    }
    // Expected response: Only 1 transaction should exist
    // Only auto-approve this transaction if one-click logins are enabled
    else if(transactions.length == 1 && !info.reviewPush) {
      // Push the single transaction
      // Throws an error if something goes wrong
      await approveTransaction(info, transactions[0].urgid);
      // Switch to success screen
      // successDetails.innerHTML = traverse(transactions[0].attributes);
      // failedAttempts = 0;
      // changeScreen("success");
      // 应该到这里就结束了
    }
    // There shouldn't be more than one transaction
    // Present all to the user
    else {
      // // If one-click logins are disabled
      // if(transactions.length == 1) {
      //   transactionsSplash.innerHTML = "Is this your login?";
      // } else {
      //   // If multiple login attempts exist
      //   transactionsSplash.innerHTML = "There's " + transactions.length + " login attempts.<br>Which one are you?";
      // }
      // // Switch to transactions screen
      // changeScreen("transactions");
      // // Also reset the transactions page
      // while(approveTable.firstChild) {
      //   approveTable.removeChild(approveTable.lastChild);
      // }
      // // For each transaction
      // for(let i = 0; i < transactions.length; i++) {
      //   let row = document.createElement("tr");
      //   // First column
      //   let c1 = document.createElement("td");
      //   let approve = document.createElement("button");
      //   approve.innerHTML = "&#x2713;";
      //   approve.className = "approve";
      //   approve.onclick = async () => {
      //     // Catch any possible errors
      //     try {
      //       // Display loading
      //       approveTable.style.display = "none";
      //       transactionsSplash.innerText = "Working...";
      //       // Approve the transaction
      //       // 应该可以直接跳到这里（但是其实这后面的都不需要，后面的都是在处理异常情况，正常情况早就处理好了）
      //       await approveTransaction(info, transactions[i].urgid);
      //       successDetails.innerHTML = traverse(transactions[i].attributes);
      //       changeScreen("success");
      //     } catch(e) {
      //       console.error(e);
      //       failedReason.innerText = `"${e}"`;
      //       changeScreen("failure");
      //     } finally {
      //       // Reset elements
      //       approveTable.style.display = "block";
      //     }
      //   }
      //   c1.appendChild(approve);

      //   // 2nd column
      //   let c2 = document.createElement("td");
      //   let p = document.createElement("p");
      //   // I have no way of knowing if array sizes vary per organization, so pick and choose isn't an option
      //   // The solution is to traverse through the JSON and find all key/value pairs
      //   p.innerHTML = traverse(transactions[i].attributes);
      //   p.style = "text-align: left; font-size: 12px; margin: 10px 0px";
      //   c2.appendChild(p);

      //   row.appendChild(c1);
      //   row.appendChild(c2);
      //   approveTable.appendChild(row);
      // }
    }
  } catch(error) {
    // failedReason.innerText = `"${error}"\n\nStack: ${error.stack}`;
    // failedAttempts = 0;
    console.error(error);
    // changeScreen("failure");
  } finally {
    // clearInterval(loadingInterval);
    // loading = false;
    // // Re-enable button
    // pushButton.disabled = false;
    // pushButton.innerHTML = "Try Again";
    // // If we couldn't login after many attemps
    // if(failedAttempts >= 4) {
    //   failedAttempts = 0;
    //   // Remind the user how Duochrome works
    //   changeScreen("failedAttempts");
    // }
  }
};


// Approves the transaction ID provided, denies all others
// Throws an exception if no transactions are active
// 通过一个请求, 在 agree_push 里面被调用
async function approveTransaction(info, txID) {
  let transactions = (await buildRequest(info, "GET", "/push/v2/device/transactions")).response.transactions;
  if(transactions.length == 0) {
    throw "No transactions found (request expired)";
  }
  for(let i = 0; i < transactions.length; i++) {
    let urgID = transactions[i].urgid;
    if(txID == urgID) {
      // Only approve this one
      let response = await buildRequest(info, "POST", "/push/v2/device/transactions/" + urgID, {"answer": "approve"}, {"txId": urgID});
      if(response.stat != "OK") {
        console.error(response);
        throw "Duo returned error status " + response.stat + " while approving login";
      }
    } else {
      // Deny all others
      // Don't bother handling the response
      buildRequest(info, "POST", "/push/v2/device/transactions/" + urgID, {"answer": "deny"}, {"txId": urgID});
    }
  }
}


// 获取请求列表, 在 agree_push 里面被调用
async function buildRequest(info, method, path, extraParam = {}, extraHeader = {}) {
  // Manually convert date to UTC
  let now = new Date();
  var utc = new Date(now.getTime() + now.getTimezoneOffset() * 60000);

  // Manually format time because JS doesn't provide regex functions for this
  let date = utc.toLocaleString('en-us', {weekday: 'long'}).substring(0, 3) + ", ";
  date += utc.getDate() + " ";
  date += utc.toLocaleString('en-us', {month: 'long'}).substring(0, 3) + " ";
  date += 1900 + utc.getYear() + " ";
  date += twoDigits(utc.getHours()) + ":";
  date += twoDigits(utc.getMinutes()) + ":";
  date += twoDigits(utc.getSeconds()) + " -0000";

  // Create canolicalized request (signature of auth header)
  // Technically, these parameters should be sorted alphabetically
  // But for our purposes we don't need to for our only extra parameter (answer=approve)
  let canonRequest = date + "\n" + method + "\n" + info.host + "\n" + path + "\n";
  let params = "";

  // We only use 1 extra parameter, but this shouldn't break for extra
  for (const [key, value] of Object.entries(extraParam)) {
    params += "&" + key + "=" + value;
  }

  // Add extra params to canonical request for auth
  if(params.length != 0) {
    // Cutoff first '&'
    params = params.substring(1);
    canonRequest += params;
    // Add '?' for URL when we make fetch request
    params = "?" + params
  }

  // Import keys (convert form Base64 back into ArrayBuffer)
  let publicKey = await window.crypto.subtle.importKey("spki", base64ToArrayBuffer(info.publicRaw), {name: "RSASSA-PKCS1-v1_5", hash: {name: 'SHA-512'},}, true, ["verify"]);
  let privateKey = await window.crypto.subtle.importKey("pkcs8", base64ToArrayBuffer(info.privateRaw), {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-512"},}, true, ["sign"]);

  // Sign canonicalized request using RSA private key
  let toEncrypt = new TextEncoder().encode(canonRequest);
  let signed = await window.crypto.subtle.sign({name: "RSASSA-PKCS1-v1_5"}, privateKey, toEncrypt);
  let verified = await window.crypto.subtle.verify({name: "RSASSA-PKCS1-v1_5"}, publicKey, signed, toEncrypt);

  // Ensure keys match
  if(!verified) {
    throw("Failed to verify signature with RSA keys");
  }

  // Required headers for all requests
  let headers = {
    "Authorization": "Basic " + window.btoa(info.pkey + ":" + arrayBufferToBase64(signed)),
    "x-duo-date": date
  }

  // Append additional headers (we only use txId during transaction reply)
  // Unlike extraParams, this won't break if more are supplied (which we don't need)
  for (const [key, value] of Object.entries(extraHeader)) {
    headers[key] = value;
  }

  let result = await fetch("https://" + info.host + path + params, {
    method: method,
    headers: headers
  }).then(response => {
    if(!response.ok) {
      console.error(response);
      throw "Duo denied handling request at " + path + " (was the device deleted?)";
    } else {
      return response.json();
    }
  });

  return result;
}



async function main(){
  var qr_code = prompt("请输入二维码");
  await activateDevice(qr_code);
  while (true) {
    agree_push();
    await new Promise(resolve => setTimeout(resolve, 1500));
  }
}

main();
