/*** Stateless Vault by Andrea Guerini is licensed under the Creative Commons Attribution 4.0 International License. 
To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/. 
Based on works by Maarten Billemont (https://github.com/Lyndir/MasterPassword/) 
and by Tom Thorogood (https://github.com/tmthrgd/mpw-js).  ***/

/* declaration of two variables: one for user and one for catching errors */
var user, error;

/* updateUSER is a function that updates user's data */
function updateUSER() {
	user = null;						/* variable user gets no object value: reset of variable 						*/
  startWork();						/* call to function startWork() 																		*/
	/* variable user becomes a new object of class USER (see vault.js): 												*/
	/* two parameters are catched using JQuery selector $("#idElement") 												*/
	/* $('id')[0] returns the first selected DOM element. value is the text entered by user.    */
	user = new USER ( $('#userName')[0].value, $('#secretPassword')[0].value);
	/* user.key contains the result of USER.calculateKey(name, password): see vault.js					*/		
	/* The then() method returns a Promise. It takes up to two arguments:  											*/
	/* callback functions for the success and failure cases of the Promise. 										*/
	/* The Promise object represents the eventual completion (or failure) of an asynchronous 		*/ 		
	/* operation, and its resulting value.																											*/
  user.key.then(
  	function() {				/*callback for success */
			doneWork();				/* call to doneWork function */
    },
    function(reason) {	/* callback for failure */
      error = reason;		/* variable error gets reason value */
      user = null;			/* variable user gets no object value: reset of variable */
      doneWork();				/* call to doneWork function*/
    }
  );
}

/* this function calls function update*/
function startWork() {
  updateHTML(true);   		/* input boolean parameter set to true */
}

/* this function calls function update*/
function doneWork() {
  updateHTML(false);			/* input boolean parameter set to false */
}

/* function updateHTML (input parameter is boolean) will update index.html elements according 	*/
/* actions done by user */
function updateHTML(working) {
	
	/* user is evaluate as a boolean variable. If it's true, var screen gets "site" string value.	*/
	/* If it's false, var screen gets "identity" string value.																		*/
	if (user) {
		var screen = "site";
	} else {
		var screen = "identity";
	}
	
  /* If screen is 'identity', class="active" is added to "identity" section. */
	/* According CSS properties, "identity" section will be displayed. */
  if (screen == 'identity') {
  	$('#identity').addClass('active');
		/* if working is false, focus() gives focus to userName element. */
    	if (!working)
      	$('#userName').focus();
  }else {
	/* if screen is not "identity", so class="active"'ll be removed from "identity"	*/
	/* section. According CSS properties, "identity" section will not be displayed. */
    $('#identity').removeClass('active');
		/* It resets userName and secretPassword text entered by user to an empty string. */
      $('#userName')[0].value = $('#secretPassword')[0].value = '';
  }
	/* If screen is 'site', class="active" is added to "site" section. */
	/* According CSS properties, "site" section will be displayed. */
  if (screen == 'site') {
  	$('#site').addClass('active');
		/* if working is false, focus() gives focus to "siteName" element. */
    	if (!working)
      	$('#siteName').focus();
  }else {
	/* if screen is not "site", so class="active"'ll be removed from "site"	section */
	/* According CSS properties, "site" section will not be displayed. */
  	$('#site').removeClass('active');
		/* The val() method returns or sets the value attribute of the selected elements. */
		/* The text() method sets or returns the text content of the selected elements. */
		/* Value attribute of siteName is set to null: Text value of sitePassword is set ti null */	
    $('#siteName').val(null);
    $('#sitePassword').text(null);
  }

  // If Working is true and screen is "identity" 
  if (working && screen == 'identity'){
		/* The find() method returns descendant elements of the selected element.										*/
		/* The attr() method sets or returns attributes and values of the selected elements.				*/
		/* class="working" is added to "identity" element; Attributes "disabled" are set for	input */
		/* and select element */	
    $('#identity').addClass('working').find('input, select').attr('disabled', 'disabled');
	}else{
		/* Otherwise if working is false or screen is not "identity", class="working" is removed from */
		/* identity element */
    $('#identity').removeClass('working').find('input, select').removeAttr('disabled');
	}
	// If Working is true and screen is "site" 
  if (working && screen == 'site'){
		/* class="working" is added to "site" element */
    $('#site').addClass('working');
	}else{
		/* Otherwise if working is false or screen is not "site", class="working" is removed from "site " */
		/* element */
    $('#site').removeClass('working');
	
    /* The text() method sets or returns the text content of the selected elements. */
		/* Text content of "error" element will be value of var error */
    $('#error').text(error);
	}
}

/* updateSite() inserts generated password in sitePassword when user is complete, else produce an error */
function updateSite() {
	/* if user is false, callback donework() function */
	if (!user) {
		doneWork(); 	/*It will input false to updateHTML()*/
    return				/* return to updateSite flow */
  }
		/* callback to startWork() function that will input true to updateHTML()*/
    startWork();
		/* call to generatePassword method for object user: inputs are values of siteName, siteCounter and pwType */
		/* The then() method returns a Promise. It takes up to two arguments:  											*/
		/* callback functions for the success and failure cases of the Promise. 										*/
		/* The Promise object represents the eventual completion (or failure) of an asynchronous 		*/ 		
		/* operation, and its resulting value.																											*/
    user.generatePassword( $('#siteName')[0].value, $('#siteCounter')[0].valueAsNumber, $('#pwType')[0].value )
       .then( function (sitePassword) {						/*case for success */
           $('#sitePassword').text(sitePassword);	/* Text method puts value of var sitePassword */
																									/* to sitePassword element  */
           doneWork();														/* call to doneWork() that enters false to updateHTML() */
       }, function (reason) {											/* case for failure */
           error = reason;												/* variable error gets reason value */
           doneWork();														/* call to doneWork() that enters false to updateHTML() */
       });
}

/* selectText gets elements */
function selectText(element) {
	/* A Selection object represents the range of text selected by the user */
	/* To obtain a Selection object for examination or manipulation, call window.getSelection(). */
  var selection = window.getSelection();  
	/* The Range interface represents a fragment of a document that can contain nodes and parts of text nodes. */
	/* A range can be created by using the Document.createRange() */
  var range = document.createRange();
	/* Sets range to contain the contents of node element (input parameter). */
  range.selectNodeContents(element);
	/* Removes all ranges from the selection, leaving the anchorNode and focusNode properties equal */
  selection.removeAllRanges();
	/* Adds a new range to selection. */
  selection.addRange(range);
}


/* This functions catches new personal data to build a new user */
$(function() {
	
	/* The on() method attaches one or more event handlers for the selected elements and child elements.*/
	/* Event handler: When user clicks on AUTHENTICATE submit button inside "identity" section's form,   */
	/* a new function calls updateUSER. This function returns false. */
  $('#identity form').on('submit', function() {
    updateUSER();
    return false;
  });
	
	/* When user changes parameter inside "site" section's input and select, updateSite() is called */
	/* Which events? The change event occurs when the value of an element has been changed.(only works */
	/* on <input>, <textarea> and <select> elements). The input event fires when the value of an <input>, */
	/* <select>, or <textarea> element has been changed. */
	/* The keyup event occurs when a keyboard key is released. */ 
  $('#site input, #site select').on('change input keyup', function() {
    updateSite();
  });
	
	/* When user clicks on "logout" button, user information are discarded. A new function sets user to */
	/* null. Click event catches user's click. */
  $('#logout').on('click', function() {
    user = null;
		/* If user had clicked on SHOW button, these style commands avoid to new generated passwords on screen */
		var pw = document.getElementById("sitePassword");	/* var pw gets "sitePassword" node */
  			pw.style.color = "rgba(51, 123, 168, 0)";     /* style.color changes text color reducing opacity */
		doneWork();																				/* calls to doneWork() that enters false to updateHTML */ 
  });
	
	/* When user changes type of password, a click event calls a new function. This function calls selectText with 
	new selected type of password */
  $('#sitePassword').on('click', function() {
    selectText(this);
	});
    doneWork(); /* calls to doneWork() that enters false to updateHTML */ 
});

/* this function allows to copy generated password to clipboard */
function copyPWToClipboard() {
	/* The select() method is used to select the contents of a text field.*/
	var pw = document.getElementById("sitePassword").select();  /*It puts "sitePassword" content in var pw    */
	/* The document.execCommand('copy') method's "copy" commands can be used to replace the clipboard's       */
	/* current contents with the selected material. These commands can be used without any special permission */
	/* if you are using them in a short-lived event handler for a user action (for example, a click handler). */
  document.execCommand('copy');			
}

/* showPassword shows generated password to user changing color properties of "sitePassword" element */
function showPassword(){
	var pw = document.getElementById("sitePassword"); /* var pw gets "sitePassword" node */
  		pw.style.color = "rgba(51, 123, 168, 0.7)"; 	/* style.color changes text color increasing opacity */
	setTimeout(function(){ 												/* To avoid snooping collateral effect, after 30 seconds */
	/* sitePassword will be hidden. setTimeout function executes a new style properties on pw to reduce opacity */
			pw.style.color = "rgba(51, 123, 168, 0)";  /* to zero */
	}, 30000);
}


