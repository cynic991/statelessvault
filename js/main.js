/*** Stateless Vault by Andrea Guerini is licensed under the Creative Commons Attribution 4.0 International License. 
To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/. 
Based on works by Maarten Billemont (https://github.com/Lyndir/MasterPassword/) 
and by Tom Thorogood (https://github.com/tmthrgd/mpw-js).  ***/

var user, error;

function updateUSER() {
    user = null;
    startWork();
    user = new USER ( $('#userName')[0].value, $('#masterPassword')[0].value);
    user.key.then(
        function() {
            doneWork();
        },
        function(reason) {
            error = reason;
            user = null;
            doneWork();
        }
    );
}
function startWork() {
    update(true);
}
function doneWork() {
    update(false);
}
function update(working) {
    var screen = user ? 'site': 'identity';

    // Screen Name
    if (screen == 'identity') {
        $('#identity').addClass('active');

        if (!working)
            $('#userName').focus();
    }
    else {
        $('#identity').removeClass('active');
        $('#userName')[0].value = $('#masterPassword')[0].value = '';
    }

    if (screen == 'site') {
        $('#site').addClass('active');

        if (!working)
            $('#siteName').focus();
    }
    else {
        $('#site').removeClass('active');
        $('#siteName').val(null);
        $('#sitePassword').text(null);
    }

    // Working
    if (working && screen == 'identity')
        $('#identity').addClass('working').find('input, select').attr('disabled', 'disabled');
    else
        $('#identity').removeClass('working').find('input, select').removeAttr('disabled');

    if (working && screen == 'site')
        $('#site').addClass('working');
    else
        $('#site').removeClass('working');

    // Error
    $('#error').text(error);
}
function updateSite() {
    if (!user) {
        doneWork();
        return
    }

    startWork();
    user.generatePassword( $('#siteName')[0].value, $('#siteCounter')[0].valueAsNumber, $('#siteType')[0].value )
       .then( function (sitePassword) {
           $('#sitePassword').text(sitePassword);
           doneWork();
       }, function (reason) {
           error = reason;
           doneWork();
       });
}
function selectText(element) {
    var doc = document, range, selection;    

    if (doc.body.createTextRange) { //ms
        range = doc.body.createTextRange();
        range.moveToElementText(element);
        range.select();
    } else if (window.getSelection) { //all others
        selection = window.getSelection();        
        range = doc.createRange();
        range.selectNodeContents(element);
        selection.removeAllRanges();
        selection.addRange(range);
    }
}


$(function() {
    $('#identity form').on('submit', function() {
        updateUSER();
        return false;
    });
    $('#site input, #site select').on('change input keyup', function() {
        updateSite();
    });
    $('#logout').on('click', function() {
        user = null;
        doneWork();
    });
    $('#sitePassword').on('click', function() {
        selectText(this);
    });

    doneWork();
});

function copyPWToClipboard() {
	var pw = document.getElementById("sitePassword").select();
  document.execCommand('copy');
}

function showPassword(){
	var pw = document.getElementById("sitePassword");
  		pw.style.color = "rgba(51, 123, 168, 0.7)"; 
}


