/*  
 *  breachcount.js will check if any passwords in a form have been involved in large scale data breaches. 
 *  Usage: Include this JavaScript in your <head>
 *
 *  The logic is as follows:
 * 
 *  1. Intercept form Submissions
 *  2. Find all password fields in the form, calculate their SHA1 hashes, and submit their hash prefix to api.pwnedpasswords.com
 *  3. Check if the local hash matches any of the returned hash rows
 *  4. Add pwncount results from (3) as hidden fields to the form
 *  5. Submit the form
 * 
 *  *  Two flags can bet set in the code below:
 *      clearPasswordFields: Clear password text before submitting
 *      includePasswordLength: Calculate and submit password length
 * 
 *  e.g 
 *         Original form POST: username=AzureDiamond&password=hunter2
 *         New form POST: username=AzureDiamond&Password+Breach+Count=1&Password+Length=9&password=
 * 
 *  Note: A result of -1 indicates an error connecting to api.pwnedpasswords.com
 * 
 */

// Customizable variables
clearPasswordFields = true
includePasswordLength = true

// checkPass will calculate the hash of the supplied password and submit a 5 character prefix
// to api.pwnedpasswords.com, and then check the result for intances of the hash.
async function checkPass(password){
    var sha1pass = SHA1(password);
    sha1pass = sha1pass.toUpperCase();
    var subsha1pass = sha1pass.substring(5);
    p = fetch("https://api.pwnedpasswords.com/range/" + sha1pass.substring(0, 5))
    .then(response => response.text())
    .then((response) => {
        var lines = response.split('\n');
        for(var i = 0;i < lines.length;i++){
            r = lines[i].split(":")
            rhash = r[0]
            count = r[1].trim()
            if (subsha1pass == rhash){
                //console.log("Match with " + count + " counts")
                return count
            }
        }
        return 0
    })
    .catch((err) => {
        console.log(err)
        return -1
    })
    return p
}
// Get all password input fields from a form
function getPwdInputs(form) {
    var ary = [];
    var inputs = form.getElementsByTagName("input");
    for (var i=0; i<inputs.length; i++) {
        if (inputs[i].type.toLowerCase() === "password") {
        ary.push(inputs[i]);
        }
    }
    return ary;
}

// Add a hidden input field to the given form
function addHiddenInput(form, name, val) {
    input = document.createElement('input');
    input.setAttribute('name', name);
    input.setAttribute('value', val);
    input.setAttribute('type', 'hidden');   
    form.appendChild(input);
}

// Intercept form submission to check if any passwords have been pwnd
document.addEventListener('submit', async (e)=>{
    e.preventDefault()
    pwinputs = getPwdInputs(e.target)
    for(i=0; i<pwinputs.length; i++){
        pwd = pwinputs[i].value
        nm = pwinputs[i].name
        if (nm == "") {
            nm = pwinputs[i].id
        }
        if (clearPasswordFields === true){
            pwinputs[i].value = ""
        }
        let pwcount = await checkPass(pwd)
        textCount = "Password Breach Count"
        textLength = "Password Length"
        if (pwinputs.length > 1 && nm != ""){
            textCount += " (" + nm + ")"
            textLength += " (" + nm + ")"
        }
        addHiddenInput(e.target, textCount, pwcount)
        if (includePasswordLength === true) {
            addHiddenInput(e.target, textLength, pwd.length)
        }
    }
    e.target.submit();
})

// SHA1 hash calculation
function SHA1(r) {
    function o(r, o) {
        return r << o | r >>> 32 - o
    }
    function e(r) {
        var o, e = "";
        for (o = 7; o >= 0; o--) e += (r >>> 4 * o & 15).toString(16);
        return e
    }
    var t, a, h, n, C, c, f, d, A, u = new Array(80),
        g = 1732584193,
        i = 4023233417,
        s = 2562383102,
        S = 271733878,
        m = 3285377520,
        p = (r = function(r) {
            r = r.replace(/\r\n/g, "\n");
            for (var o = "", e = 0; e < r.length; e++) {
                var t = r.charCodeAt(e);
                t < 128 ? o += String.fromCharCode(t) : t > 127 && t < 2048 ? (o += String.fromCharCode(t >> 6 | 192), o += String.fromCharCode(63 & t | 128)) : (o += String.fromCharCode(t >> 12 | 224), o += String.fromCharCode(t >> 6 & 63 | 128), o += String.fromCharCode(63 & t | 128))
            }
            return o
        }(r)).length,
        l = new Array;
    for (a = 0; a < p - 3; a += 4) h = r.charCodeAt(a) << 24 | r.charCodeAt(a + 1) << 16 | r.charCodeAt(a + 2) << 8 | r.charCodeAt(a + 3), l.push(h);
    switch (p % 4) {
        case 0:
            a = 2147483648;
            break;
        case 1:
            a = r.charCodeAt(p - 1) << 24 | 8388608;
            break;
        case 2:
            a = r.charCodeAt(p - 2) << 24 | r.charCodeAt(p - 1) << 16 | 32768;
            break;
        case 3:
            a = r.charCodeAt(p - 3) << 24 | r.charCodeAt(p - 2) << 16 | r.charCodeAt(p - 1) << 8 | 128
    }
    for (l.push(a); l.length % 16 != 14;) l.push(0);
    for (l.push(p >>> 29), l.push(p << 3 & 4294967295), t = 0; t < l.length; t += 16) {
        for (a = 0; a < 16; a++) u[a] = l[t + a];
        for (a = 16; a <= 79; a++) u[a] = o(u[a - 3] ^ u[a - 8] ^ u[a - 14] ^ u[a - 16], 1);
        for (n = g, C = i, c = s, f = S, d = m, a = 0; a <= 19; a++) A = o(n, 5) + (C & c | ~C & f) + d + u[a] + 1518500249 & 4294967295, d = f, f = c, c = o(C, 30), C = n, n = A;
        for (a = 20; a <= 39; a++) A = o(n, 5) + (C ^ c ^ f) + d + u[a] + 1859775393 & 4294967295, d = f, f = c, c = o(C, 30), C = n, n = A;
        for (a = 40; a <= 59; a++) A = o(n, 5) + (C & c | C & f | c & f) + d + u[a] + 2400959708 & 4294967295, d = f, f = c, c = o(C, 30), C = n, n = A;
        for (a = 60; a <= 79; a++) A = o(n, 5) + (C ^ c ^ f) + d + u[a] + 3395469782 & 4294967295, d = f, f = c, c = o(C, 30), C = n, n = A;
        g = g + n & 4294967295, i = i + C & 4294967295, s = s + c & 4294967295, S = S + f & 4294967295, m = m + d & 4294967295
    }
    return (A = e(g) + e(i) + e(s) + e(S) + e(m)).toLowerCase()
}