if (typeof ($) == 'undefined') {
    window.$ = jQuery.noConflict();
}
let daMapInfo = null;
let daWhichButton = null;
let daSocket = null;
let daChatHistory = [];
let daCheckinCode = null;
let daCheckingIn = 0;
let daShowingHelp = 0;
let daIframeEmbed;
daIframeEmbed = window.location !== window.parent.location;
let daJsEmbed = {% if is_js %}{{ js_target | tojson }}{% else %}false{% endif %};
let daAllowGoingBack = {% if allow_going_back %}true{% else %}false{% endif %};
let daSteps = {{ steps }};
let daIsUser = {{ is_user }};
let daChatStatus = {{ chat_status | tojson }};
let daChatAvailable = {{ chat_available | tojson }};
let daChatPartnersAvailable = 0;
let daPhoneAvailable = false;
let daChatMode = {{ chat_mode | tojson }};
let daSendChanges = {{ send_changes }};
let daInitialized = false;
let daNotYetScrolled = true;
let daBeingControlled = {{ being_controlled }};
let daInformedChanged = false;
let daInformed = {{ user_id_string | tojson }};
let daShowingSpinner = false;
let daSpinnerTimeout = null;
let daSubmitter = null;
let daUsingGA = {% if ga_id is not none %}true{% else %}false{% endif %};
let daUsingSegment = {% if segment_id is not none %}true{% else %}false{% endif %};
let daDoAction = {{ do_action }};
let daQuestionID = {{ question_id_dict | tojson }};
let daCsrf = {{ csrf | tojson }};
let daShowIfInProcess = false;
let daFieldsToSkip = ['_checkboxes', '_empties', '_ml_info', '_back_one', '_files', '_files_inline', '_question_name', '_the_image', '_save_as', '_success', '_datatypes', '_event', '_visible', '_tracker', '_track_location', '_varnames', '_next_action', '_next_action_to_set', 'ajax', 'json', 'informed', 'csrf_token', '_action', '_order_changes', '_collect', '_list_collect_list', '_null_question'];
let daVarLookup = Object();
let daVarLookupRev = Object();
let daVarLookupMulti = Object();
let daVarLookupRevMulti = Object();
let daVarLookupSelect = Object();
let daTargetDiv;
let daComboBoxes = Object();
let daGlobalEval = eval;
let daInterviewUrl = {{ url_for('index.index', **index_params) | tojson }};
let daLocationBar = {{ location_bar | tojson }};
let daPostURL = {{ url_for('index.index', **index_params_external) | tojson }};
let daYamlFilename = {{ yaml_filename | tojson }};
let daFetchAcceptIncoming = false;
let daFetchAjaxTimeout = null;
let daFetchAjaxTimeoutRunning = null;
let daFetchAjaxTimeoutFetchAfter = null;
let daShowHideHappened = false;
if (daJsEmbed) {
    daTargetDiv = '#' + daJsEmbed;
} else {
    daTargetDiv = "#dabody";
}
let daNotificationContainer = {{ NOTIFICATION_CONTAINER | tojson }};
let daNotificationMessage = {{ NOTIFICATION_MESSAGE | tojson }};
Object.defineProperty(String.prototype, "daSprintf", {
    value: function () {
        let args = Array.from(arguments),
            i = 0;

        function defaultNumber(iValue) {
            return iValue !== undefined && !isNaN(iValue) ? iValue : "0";
        }

        function defaultString(iValue) {
            return iValue === undefined ? "" : "" + iValue;
        }

        return this.replace(
            /%%|%([+\-])?([^1-9])?(\d+)?(\.\d+)?([deEfhHioQqs])/g,
            function (match, sign, filler, scale, precision, type) {
                let strOut, space, value;
                let asNumber = false;
                if (match === "%%") return "%";
                if (i >= args.length) return match;
                value = args[i];
                while (Array.isArray(value)) {
                    args.splice(i, 1);
                    for (let j = i; value.length > 0; j++)
                        args.splice(j, 0, value.shift());
                    value = args[i];
                }
                i++;
                if (filler === undefined) filler = " "; // default
                if (scale === undefined && !isNaN(filler)) {
                    scale = filler;
                    filler = " ";
                }
                if (sign === undefined) sign = "sqQ".indexOf(type) >= 0 ? "+" : "-"; // default
                if (scale === undefined) scale = 0; // default
                if (precision === undefined) precision = ".0"; // default
                scale = parseInt(scale);
                precision = parseInt(precision.substr(1));
                switch (type) {
                    case "d":
                    case "i":
                        // decimal integer
                        asNumber = true;
                        strOut = parseInt(defaultNumber(value));
                        if (precision > 0) strOut += "." + "0".repeat(precision);
                        break;
                    case "e":
                    case "E":
                        // float in exponential notation
                        asNumber = true;
                        strOut = parseFloat(defaultNumber(value));
                        if (precision == 0) strOut = strOut.toExponential();
                        else strOut = strOut.toExponential(precision);
                        if (type === "E") strOut = strOut.replace("e", "E");
                        break;
                    case "f":
                        // decimal float
                        asNumber = true;
                        strOut = parseFloat(defaultNumber(value));
                        if (precision != 0) strOut = strOut.toFixed(precision);
                        break;
                    case "o":
                    case "h":
                    case "H":
                        // Octal or Hexagesimal integer notation
                        strOut =
                            "\\" +
                            (type === "o" ? "0" : type) +
                            parseInt(defaultNumber(value)).toString(type === "o" ? 8 : 16);
                        break;
                    case "q":
                        // single quoted string
                        strOut = "'" + defaultString(value) + "'";
                        break;
                    case "Q":
                        // double quoted string
                        strOut = '"' + defaultString(value) + '"';
                        break;
                    default:
                        // string
                        strOut = defaultString(value);
                        break;
                }
                if (typeof strOut != "string") strOut = "" + strOut;
                if ((space = strOut.length) < scale) {
                    if (asNumber) {
                        if (sign === "-") {
                            if (strOut.indexOf("-") < 0)
                                strOut = filler.repeat(scale - space) + strOut;
                            else
                                strOut =
                                    "-" +
                                    filler.repeat(scale - space) +
                                    strOut.replace("-", "");
                        } else {
                            if (strOut.indexOf("-") < 0)
                                strOut = "+" + filler.repeat(scale - space - 1) + strOut;
                            else
                                strOut =
                                    "-" +
                                    filler.repeat(scale - space) +
                                    strOut.replace("-", "");
                        }
                    } else {
                        if (sign === "-") strOut = filler.repeat(scale - space) + strOut;
                        else strOut = strOut + filler.repeat(scale - space);
                    }
                } else if (asNumber && sign === "+" && strOut.indexOf("-") < 0)
                    strOut = "+" + strOut;
                return strOut;
            }
        );
    }
});
Object.defineProperty(window, "daSprintf", {
    value: function (str, ...rest) {
        if (typeof str == "string")
            return String.prototype.daSprintf.apply(str, rest);
        return "";
    }
});
function daGoToAnchor(target) {
    if (daJsEmbed) {
        scrollTarget = $(target).first().position().top - 60;
    } else {
        scrollTarget = $(target).first().offset().top - 60;
    }
    if (scrollTarget != null) {
        if (daJsEmbed) {
            $(daTargetDiv).animate({
                scrollTop: scrollTarget
            }, 500);
        } else {
            $("html, body").animate({
                scrollTop: scrollTarget
            }, 500);
        }
    }
}
function dabtoa(str) {
    return window.btoa(str).replace(/[\n=]/g, '');
}
function daatob(str) {
    return window.atob(str);
}
function hideTablist() {
    let anyTabs = $("#daChatAvailable").is(":visible")
        || $("daPhoneAvailable").is(":visible")
        || $("#dahelptoggle").is(":visible");
    if (anyTabs) {
        $("#nav-bar-tab-list").removeClass("dainvisible");
        $("#daquestionlabel").parent().removeClass("dainvisible");
    } else {
        $("#nav-bar-tab-list").addClass("dainvisible");
        $("#daquestionlabel").parent().addClass("dainvisible");
    }
}
function getFields() {
    let allFields = [];
    for (let rawFieldName in daVarLookup) {
        if (daVarLookup.hasOwnProperty(rawFieldName)) {
            let fieldName = atob(rawFieldName);
            if (allFields.indexOf(fieldName) === -1) {
                allFields.push(fieldName);
            }
        }
    }
    return allFields;
}
let daGetFields = getFields;
function daAppendIfExists(fieldName, theArray) {
    let elem = $("[name='" + fieldName + "']");
    if (elem.length > 0) {
        for (let i = 0; i < theArray.length; ++i) {
            if (theArray[i] === elem[0]) {
                return;
            }
        }
        theArray.push(elem[0]);
    }
}
function getField(fieldName, notInDiv) {
    if (daVarLookupSelect[fieldName]) {
        let n = daVarLookupSelect[fieldName].length;
        for (let i = 0; i < n; ++i) {
            let elem = daVarLookupSelect[fieldName][i].select;
            if (!$(elem).prop('disabled')) {
                let showifParents = $(elem).parents(".dajsshowif,.dashowif");
                if (showifParents.length === 0 || $(showifParents[0]).data("isVisible") === '1') {
                    if (notInDiv && $.contains(notInDiv, elem)) {
                        continue;
                    }
                    return elem;
                }
            }
        }
    }
    let fieldNameEscaped = dabtoa(fieldName);
    let possibleElements = [];
    daAppendIfExists(fieldNameEscaped, possibleElements);
    if (daVarLookupMulti.hasOwnProperty(fieldNameEscaped)) {
        for (let i = 0; i < daVarLookupMulti[fieldNameEscaped].length; ++i) {
            daAppendIfExists(daVarLookupMulti[fieldNameEscaped][i], possibleElements);
        }
    }
    let returnVal = null;
    for (let i = 0; i < possibleElements.length; ++i) {
        if (!$(possibleElements[i]).prop('disabled')) {
            let showifParents = $(possibleElements[i]).parents(".dajsshowif,.dashowif");
            if (showifParents.length === 0 || $(showifParents[0]).data("isVisible") == '1') {
                if (notInDiv && $.contains(notInDiv, possibleElements[i])) {
                    continue;
                }
                returnVal = possibleElements[i];
            }
        }
    }
    return returnVal;
}
let daGetField = getField;
function setField(fieldName, val) {
    let elem = daGetField(fieldName);
    if (elem == null) {
        console.log('setField: reference to non-existent field ' + fieldName);
        return;
    }
    if ($(elem).attr('type') === "checkbox") {
        if (val) {
            if ($(elem).prop('checked') != true) {
                $(elem).prop('checked', true);
                $(elem).trigger('change');
            }
        } else {
            if ($(elem).prop('checked') != false) {
                $(elem).prop('checked', false);
                $(elem).trigger('change');
            }
        }
    } else if ($(elem).attr('type') === "radio") {
        let fieldNameEscaped = $(elem).attr('name').replace(/([:.\[\],=])/g, "\\$1");
        let wasSet = false;
        $("input[name='" + fieldNameEscaped + "']").each(function () {
            if ($(this).val() == val) {
                if ($(this).prop('checked') != true) {
                    $(this).prop('checked', true);
                    $(this).trigger('change');
                }
                wasSet = true;
                return false;
            }
        });
        if (!wasSet) {
            console.log('setField: could not set radio button ' + fieldName + ' to ' + val);
        }
    } else {
        if ($(elem).val() != val) {
            $(elem).val(val);
            $(elem).trigger('change');
        }
    }
}
let daSetField = setField;
function val(fieldName) {
    let elem = daGetField(fieldName);
    let theVal = "";
    if (elem == null) {
        return null;
    }
    if ($(elem).attr('type') === "checkbox") {
        theVal = !!$(elem).prop('checked');
    } else if ($(elem).attr('type') === "radio") {
        let fieldNameEscaped = $(elem).attr('name').replace(/([:.\[\],=])/g, "\\$1");
        theVal = $("input[name='" + fieldNameEscaped + "']:checked").val();
        if (typeof (theVal) == 'undefined') {
            theVal = null;
        } else {
            if (theVal === 'True') {
                theVal = true;
            } else if (theVal === 'False') {
                theVal = false;
            }
        }
    } else if ($(elem).prop('tagName') === "SELECT" && $(elem).hasClass('damultiselect') && daVarLookupSelect[fieldName]) {
        let n = daVarLookupSelect[fieldName].length;
        for (let i = 0; i < n; ++i) {
            if (daVarLookupSelect[fieldName][i].select === elem) {
                return $(daVarLookupSelect[fieldName][i].option).prop('selected');
            }
        }
    } else {
        theVal = $(elem).val();
    }
    return theVal;
}
let da_val = val;
function daFormAsJSON() {
    let formData = $("#daform").serializeArray();
    let data = Object();
    let n = formData.length;
    for (let i = 0; i < n; ++i) {
        let key = formData[i]['name'];
        let val = formData[i]['value'];
        if ($.inArray(key, daFieldsToSkip) !== -1 || key.indexOf('_ignore') === 0) {
            continue;
        }
        if (typeof daVarLookupRev[key] != "undefined") {
            data[atob(daVarLookupRev[key])] = val;
        } else {
            data[atob(key)] = val;
        }
    }
    return JSON.stringify(data);
}
let daMessageLog = JSON.parse(atob({{ message_log }}));
function daPreloadImage(url) {
    let img = new Image();
    img.src = url;
}
daPreloadImage('{{ url_for('static', filename='app/chat.ico', v=da_version) }}');
function daShowHelpTab() {
    $('#dahelptoggle').tab('show');
}
function addCsrfHeader(xhr, settings) {
    if (daJsEmbed && !/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type)) {
        xhr.setRequestHeader("X-CSRFToken", daCsrf);
    }
}
function flash(message, priority, clear) {
    if (priority == null) {
        priority = 'info'
    }
    const daFlash = $("#daflash");
    if (!daFlash.length) {
        $(daTargetDiv).append(daSprintf(daNotificationContainer, ""));
    }
    if (clear) {
        daFlash.empty();
    }
    if (message != null) {
        daFlash.append(daSprintf(daNotificationMessage, priority, message));
        if (priority === 'success') {
            setTimeout(function () {
                $("#daflash .alert-success").hide(300, function () {
                    $(this).remove();
                });
            }, 3000);
        }
    }
}
let da_flash = flash;
function url_action(action, args) {
    if (args == null) {
        args = {};
    }
    data = {action: action, arguments: args};
    let url;
    if (daJsEmbed) {
        url = daPostURL + "&action=" + encodeURIComponent(btoa(JSON_stringify(data)))
    } else {
        if (daLocationBar.indexOf('?') !== -1) {
            url = daLocationBar + "&action=" + encodeURIComponent(btoa(JSON_stringify(data)))
        } else {
            url = daLocationBar + "?action=" + encodeURIComponent(btoa(JSON_stringify(data)))
        }
    }
    return url;
}
let da_url_action = url_action;
function action_call(action, args, callback) {
    if (args == null) {
        args = {};
    }
    if (callback == null) {
        callback = function () {
        };
    }
    let data = {action: action, arguments: args};
    let url;
    if (daJsEmbed) {
        url = daPostURL + "&action=" + encodeURIComponent(btoa(JSON_stringify(data)))
    } else {
        url = daInterviewUrl + "&action=" + encodeURIComponent(btoa(JSON_stringify(data)))
    }
    return $.ajax({
        type: "GET",
        url: url,
        success: callback,
        beforeSend: addCsrfHeader,
        xhrFields: {
            withCredentials: true
        },
        error: function (xhr, status, error) {
            setTimeout(function () {
                daProcessAjaxError(xhr, status, error);
            }, 0);
        }
    });
}
let da_action_call = action_call;
let url_action_call = action_call;
function action_perform(action, args) {
    if (args == null) {
        args = {};
    }
    let data = {action: action, arguments: args};
    daSpinnerTimeout = setTimeout(daShowSpinner, 1000);
    return $.ajax({
        type: "POST",
        url: daInterviewUrl,
        beforeSend: addCsrfHeader,
        xhrFields: {
            withCredentials: true
        },
        data: $.param({_action: btoa(JSON_stringify(data)), csrf_token: daCsrf, ajax: 1}),
        success: function (data) {
            setTimeout(function () {
                daProcessAjax(data, $("#daform"), 1);
            }, 0);
        },
        error: function (xhr, status, error) {
            setTimeout(function () {
                daProcessAjaxError(xhr, status, error);
            }, 0);
        },
        dataType: 'json'
    });
}
let da_action_perform = action_perform;
let url_action_perform = action_perform;
function action_perform_with_next(action, args, next_data) {
    //console.log("action_perform_with_next: " + action + " | " + next_data)
    if (args == null) {
        args = {};
    }
    let data = {action: action, arguments: args};
    daSpinnerTimeout = setTimeout(daShowSpinner, 1000);
    return $.ajax({
        type: "POST",
        url: daInterviewUrl,
        beforeSend: addCsrfHeader,
        xhrFields: {
            withCredentials: true
        },
        data: $.param({
            _action: btoa(JSON_stringify(data)),
            _next_action_to_set: btoa(JSON_stringify(next_data)),
            csrf_token: daCsrf,
            ajax: 1
        }),
        success: function (data) {
            setTimeout(function () {
                daProcessAjax(data, $("#daform"), 1);
            }, 0);
        },
        error: function (xhr, status, error) {
            setTimeout(function () {
                daProcessAjaxError(xhr, status, error);
            }, 0);
        },
        dataType: 'json'
    });
}
let da_action_perform_with_next = action_perform_with_next;
let url_action_perform_with_next = action_perform_with_next;
function get_interview_variables(callback) {
    if (callback == null) {
        callback = function () {
        };
    }
    return $.ajax({
        type: "GET",
        url: "{{ url_for('util.get_variables', i=yaml_filename) }}",
        success: callback,
        beforeSend: addCsrfHeader,
        xhrFields: {
            withCredentials: true
        },
        error: function (xhr, status, error) {
            setTimeout(function () {
                daProcessAjaxError(xhr, status, error);
            }, 0);
        }
    });
}
let da_get_interview_variables = get_interview_variables;
function daInformAbout(subject, chatMessage) {
    if (subject in daInformed || (subject !== 'chatmessage' && !daIsUser)) {
        return;
    }
    if (daShowingHelp && subject !== 'chatmessage') {
        daInformed[subject] = 1;
        daInformedChanged = true;
        return;
    }
    if (daShowingHelp && subject === 'chatmessage') {
        return;
    }
    let target;
    let message;
    let waitPeriod = 3000;
    if (subject === 'chat') {
        target = "#daChatAvailable a";
        message = {{ word("Get help through live chat by clicking here.") | tojson }};
    } else if (subject === 'chatmessage') {
        target = "#daChatAvailable a";
        //message = {{ word("A chat message has arrived.") | tojson }};
        message = chatMessage;
    } else if (subject === 'phone') {
        target = "#daPhoneAvailable a";
        message = {{ word("Click here to get help over the phone.") | tojson }};
    } else {
        return;
    }
    if (subject !== 'chatmessage') {
        daInformed[subject] = 1;
        daInformedChanged = true;
    }
    if (subject === 'chatmessage') {
        $(target).popover({
            "content": message,
            "placement": "bottom",
            "trigger": "manual",
            "container": "body",
            "title": {{ word("New chat message") | tojson }}
        });
    } else {
        $(target).popover({
            "content": message,
            "placement": "bottom",
            "trigger": "manual",
            "container": "body",
            "title": {{ word("Live chat is available") | tojson }}
        });
    }
    $(target).popover('show');
    setTimeout(function () {
        $(target).popover('dispose');
        $(target).removeAttr('title');
    }, waitPeriod);
}
// function daCloseSocket(){
//   if (typeof daSocket !== 'undefined' && daSocket.connected){
//     //daSocket.emit('terminate');
//     //io.unwatch();
//   }
// }
function daPublishMessage(data) {
    let newDiv = document.createElement('li');
    $(newDiv).addClass("list-group-item");
    if (data.is_self) {
        $(newDiv).addClass("list-group-item-primary dalistright");
    } else {
        $(newDiv).addClass("list-group-item-secondary dalistleft");
    }
    $(newDiv).html(data.message);
    $("#daCorrespondence").append(newDiv);
}
function daScrollChat() {
    let chatScroller = $("#daCorrespondence");
    if (chatScroller.length) {
        let height = chatScroller[0].scrollHeight;
        if (height === 0) {
            daNotYetScrolled = true;
            return;
        }
        chatScroller.animate({scrollTop: height}, 800);
    } else {
        console.log("daScrollChat: error");
    }
}
function daScrollChatFast() {
    let chatScroller = $("#daCorrespondence");
    if (chatScroller.length) {
        let height = chatScroller[0].scrollHeight;
        if (height === 0) {
            daNotYetScrolled = true;
            return;
        }
        chatScroller.scrollTop(height);
    } else {
        console.log("daScrollChatFast: error");
    }
}
function daSender() {
    const daMessage = $("#daMessage");
    if (daMessage.val().length) {
        daSocket.emit('chatmessage', {data:daMessage.val(), i: daYamlFilename});
        daMessage.val("");
        daMessage.focus();
    }
    return false;
}
function daShowControl(mode) {
    const body = $("body");
    if (body.hasClass("dacontrolled")) {
        return;
    }
    $('input[type="submit"], button[type="submit"]').prop("disabled", true);
    body.addClass("dacontrolled");
    const newDiv = $(document.createElement('div'));
    newDiv.addClass("datop-alert col-xs-10 col-sm-7 col-md-6 col-lg-5 dacol-centered");
    newDiv.html({{ word("Your screen is being controlled by an operator.") | tojson }})
    newDiv.attr('id', "dacontrolAlert");
    newDiv.css("display", "none");
    newDiv.appendTo($(daTargetDiv));
    if (mode === 'animated') {
        newDiv.slideDown();
    } else {
        newDiv.show();
    }
}
function daHideControl() {
    const body = $("body");
    if (!body.hasClass("dacontrolled")) {
        return;
    }
    $('input[type="submit"], button[type="submit"]').prop("disabled", false);
    body.removeClass("dacontrolled");
    const daControlAlert = $("#dacontrolAlert")
    daControlAlert.html({{ word("The operator is no longer controlling your screen.") | tojson }});
    setTimeout(function () {
        daControlAlert.slideUp(300, function () {
            daControlAlert.remove();
        });
    }, 2000);
}
function daInitializeSocket() {
    if (daSocket != null) {
        if (daSocket.connected) {
            if (daChatStatus === 'ready') {
                daSocket.emit('connectagain', {i: daYamlFilename});
            }
            if (daBeingControlled) {
                daShowControl('animated');
                daSocket.emit('start_being_controlled', {i: daYamlFilename});
            }
        } else {
            daSocket.connect();
        }
        return;
    }
    if (location.protocol === 'http:' || document.location.protocol === 'http:') {
        daSocket = io.connect('http://' + document.domain + '/wsinterview', {
            path: '{{ ROOT }}ws/socket.io',
            query: "i=" + daYamlFilename
        });
    }
    if (location.protocol === 'https:' || document.location.protocol === 'https:') {
        daSocket = io.connect('https://' + document.domain + '/wsinterview', {
            path: '{{ ROOT }}ws/socket.io',
            query: "i=" + daYamlFilename
        });
    }
    if (daSocket != null) {
        daSocket.on('connect', function () {
            if (daSocket == null) {
                console.log("Error: socket is null");
                return;
            }
            if (daChatStatus === 'ready') {
                daChatStatus = 'on';
                daDisplayChat();
                daPushChanges();
                //daTurnOnChat();
                //console.log("Emitting chat_log from on connect");
                daSocket.emit('chat_log', {i: daYamlFilename});
            }
            if (daBeingControlled) {
                daShowControl('animated')
                daSocket.emit('start_being_controlled', {i: daYamlFilename});
            }
        });
        daSocket.on('chat_log', function (arg) {
            //console.log("Got chat_log");
            $("#daCorrespondence").html('');
            daChatHistory = [];
            let messages = arg.data;
            for (let i = 0; i < messages.length; ++i) {
                daChatHistory.push(messages[i]);
                daPublishMessage(messages[i]);
            }
            daScrollChatFast();
        });
        daSocket.on('terminate', function () {
            daSocket.disconnect();
        });
        daSocket.on('controllerstart', function () {
            daBeingControlled = true;
            daShowControl('animated');
        });
        daSocket.on('controllerexit', function () {
            daBeingControlled = false;
            //console.log("Hiding control 2");
            daHideControl();
            if (daChatStatus !== 'on') {
                if (daSocket !== null && daSocket.connected) {
                    //console.log('Terminating interview socket because control over');
                    daSocket.emit('terminate');
                }
            }
        });
        daSocket.on('reconnected', function () {
            daChatStatus = 'on';
            daDisplayChat();
            daPushChanges();
            daTurnOnChat();
            daSocket.emit('chat_log', {i: daYamlFilename});
        });
        daSocket.on('mymessage', function (arg) {
            $("#daPushResult").html(arg.data);
        });
        daSocket.on('departure', function (arg) {
            if (arg.numpartners == 0) {
                daCloseChat();
            }
        });
        daSocket.on('chatmessage', function (arg) {
            daChatHistory.push(arg.data);
            daPublishMessage(arg.data);
            daScrollChat();
            daInformAbout('chatmessage', arg.data.message);
        });
        daSocket.on('newpage', function (incoming) {
            let data = incoming.obj;
            daProcessAjax(data, $("#daform"), 1);
        });
        daSocket.on('controllerchanges', function (data) {
            let valArray = Object();
            let values = JSON.parse(data.parameters);
            for (let i = 0; i < values.length; i++) {
                valArray[values[i].name] = values[i].value;
            }
            $("#daform").each(function () {
                $(this).find(':input').each(function () {
                    const $this = $(this);
                    let type = $this.attr('type');
                    let name = $this.attr('name');
                    if (type === 'checkbox') {
                        if (name in valArray) {
                            if (valArray[name] === 'True') {
                                if ($this.prop('checked') != true) {
                                    $this.prop('checked', true);
                                    $this.trigger('change');
                                }
                            } else {
                                if ($this.prop('checked') != false) {
                                    $this.prop('checked', false);
                                    $this.trigger('change');
                                }
                            }
                        } else {
                            if ($this.prop('checked') != false) {
                                $this.prop('checked', false);
                                $this.trigger('change');
                            }
                        }
                    } else if (type === 'radio') {
                        if (name in valArray) {
                            if (valArray[name] == $this.val()) {
                                if ($this.prop('checked') != true) {
                                    $this.prop('checked', true);
                                    $this.trigger('change');
                                }
                            } else {
                                if ($this.prop('checked') != false) {
                                    $this.prop('checked', false);
                                    $this.trigger('change');
                                }
                            }
                        }
                    } else if ($this.data().hasOwnProperty('sliderMax')) {
                        $this.slider('setValue', parseInt(valArray[name]));
                    } else {
                        if (name in valArray) {
                            $this.val(valArray[name]);
                        }
                    }
                });
            });
            if (data.clicked) {
                const clickIt = $(data.clicked)
                clickIt.prop("disabled", false);
                clickIt.addClass("da-click-selected");
                if (clickIt.prop("tagName") === 'A' && typeof clickIt.attr('href') != 'undefined' && (clickIt.attr('href').indexOf('javascript') === 0 || clickIt.attr('href').indexOf('#') === 0)) {
                    setTimeout(function () {
                        clickIt.removeClass("da-click-selected");
                    }, 2200);
                }
                setTimeout(function () {
                    clickIt.click();
                }, 200);
            }
        });
    }
}
let daCheckinSeconds = {{ the_checkin_interval }};
let daCheckinInterval = null;
let daReloader = null;
let daDisable = null;
let daChatRoles = {{ roles | tojson }};
let daChatPartnerRoles = {{ partner_roles | tojson }};
function daUnfakeHtmlResponse(text) {
    text = text.substr(text.indexOf('ABCDABOUNDARYSTARTABC') + 21);
    text = text.substr(0, text.indexOf('ABCDABOUNDARYENDABC')).replace(/\s/g, '');
    text = atob(text);
    return text;
}
function daInjectTrim(handler) {
    return function (element, event) {
        if (element.tagName === "TEXTAREA" || (element.tagName === "INPUT" && element.type !== "password" && element.type !== "date" && element.type !== "datetime" && element.type !== "file")) {
            setTimeout(function () {
                element.value = $.trim(element.value);
            }, 10);
        }
        return handler.call(this, element, event);
    };
}
function daInvalidHandler(form, validator) {
    let errors = validator.numberOfInvalids();
    let scrollTarget = null;
    if (errors && $(validator.errorList[0].element).parents('.da-form-group').length > 0) {
        if (daJsEmbed) {
            scrollTarget = $(validator.errorList[0].element).parents('.da-form-group').first().position().top - 60;
        } else {
            scrollTarget = $(validator.errorList[0].element).parents('.da-form-group').first().offset().top - 60;
        }
    }
    if (scrollTarget != null) {
        if (daJsEmbed) {
            $(daTargetDiv).animate({
                scrollTop: scrollTarget
            }, 1000);
        } else {
            $("html, body").animate({
                scrollTop: scrollTarget
            }, 1000);
        }
    }
}
function daValidationHandler(form) {
    let visibleElements = [];
    let seen = Object();
    $(form).find("input, select, textarea").filter(":not(:disabled)").each(function () {
        if ($(this).attr('name') && $(this).attr('type') !== "hidden" && (($(this).hasClass('da-active-invisible') && $(this).parent().is(":visible")) || $(this).is(":visible"))) {
            let theName = $(this).attr('name');
            //console.log("Including an element " + theName);
            if (!seen.hasOwnProperty(theName)) {
                visibleElements.push(theName);
                seen[theName] = 1;
            }
        }
    });
    $(form).find("input[name='_visible']").val(btoa(JSON_stringify(visibleElements)));
    $(form).each(function () {
        $(this).find(':input').off('change', daPushChanges);
    });
    $("meta[name=viewport]").attr('content', "width=device-width, minimum-scale=1.0, maximum-scale=1.0, initial-scale=1.0");
    if (daCheckinInterval != null) {
        clearInterval(daCheckinInterval);
    }
    daDisable = setTimeout(function () {
        $(form).find('input[type="submit"]').prop("disabled", true);
        $(form).find('button[type="submit"]').prop("disabled", true);
    }, 1);
    if (daWhichButton != null) {
        $(".da-field-buttons .btn-da").each(function () {
            if (this !== daWhichButton) {
                $(this).removeClass("{{ button_style }}primary {{ button_style }}info {{ button_style }}warning {{ button_style }}danger {{ button_style }}secondary");
                $(this).addClass("{{ button_style }}light");
            }
        });
        if ($(daWhichButton).hasClass("{{ button_style }}success")) {
            $(daWhichButton).removeClass("{{ button_style }}success");
            $(daWhichButton).addClass("{{ button_style }}primary");
        } else {
            $(daWhichButton).removeClass("{{ button_style }}primary {{ button_style }}info {{ button_style }}warning {{ button_style }}danger {{ button_style }}success {{ button_style }}light");
            $(daWhichButton).addClass("{{ button_style }}secondary");
        }
    }
    let tableOrder = {};
    let tableOrderChanges = {};
    $("a.datableup").each(function () {
        let tableName = $(this).data('tablename');
        if (!tableOrder.hasOwnProperty(tableName)) {
            tableOrder[tableName] = [];
        }
        tableOrder[tableName].push(parseInt($(this).data('tableitem')));
    });
    let tableChanged = false;
    for (let tableName in tableOrder) {
        if (tableOrder.hasOwnProperty(tableName)) {
            let n = tableOrder[tableName].length;
            for (let i = 0; i < n; ++i) {
                if (i != tableOrder[tableName][i]) {
                    tableChanged = true;
                    if (!tableOrderChanges.hasOwnProperty(tableName)) {
                        tableOrderChanges[tableName] = [];
                    }
                    tableOrderChanges[tableName].push([tableOrder[tableName][i], i])
                }
            }
        }
    }
    if (tableChanged) {
        $('<input>').attr({
            type: 'hidden',
            name: '_order_changes',
            value: JSON.stringify(tableOrderChanges)
        }).appendTo($(form));
    }
    let collectToDelete = [];
    $(".dacollectunremove:visible").each(function () {
        collectToDelete.push(parseInt($(this).parent().parent().data('collectnum')));
    });
    let lastOk = parseInt($(".dacollectremove:visible, .dacollectremoveexisting:visible").last().parent().parent().data('collectnum'));
    $(".dacollectremove, .dacollectremoveexisting").each(function () {
        if (parseInt($(this).parent().parent().data('collectnum')) > lastOk) {
            collectToDelete.push(parseInt($(this).parent().parent().data('collectnum')));
        }
    });
    if (collectToDelete.length > 0) {
        $('<input>').attr({
            type: 'hidden',
            name: '_collect_delete',
            value: JSON.stringify(collectToDelete)
        }).appendTo($(form));
    }
    $("select.damultiselect:not(:disabled)").each(function () {
        let showifParents = $(this).parents(".dajsshowif,.dashowif");
        if (showifParents.length === 0 || $(showifParents[0]).data("isVisible") == '1') {
            $(this).find('option').each(function () {
                $('<input>').attr({
                    type: 'hidden',
                    name: $(this).val(),
                    value: $(this).prop('selected') ? 'True' : 'False'
                }).appendTo($(form));
            });
        }
        $(this).prop('disabled', true);
    });
    daWhichButton = null;
    if (daSubmitter != null) {
        $('<input>').attr({
            type: 'hidden',
            name: daSubmitter.name,
            value: daSubmitter.value
        }).appendTo($(form));
    }
    if (daInformedChanged) {
        $("<input>").attr({
            type: 'hidden',
            name: 'informed',
            value: Object.keys(daInformed).join(',')
        }).appendTo($(form));
    }
    $('<input>').attr({
        type: 'hidden',
        name: 'ajax',
        value: '1'
    }).appendTo($(form));
    daSpinnerTimeout = setTimeout(daShowSpinner, 1000);
    let do_iframe_upload = false;
    inline_succeeded = false;
    if ($('input[name="_files"]').length) {
        let filesToRead = 0;
        let filesRead = 0;
        let newFileList = Array();
        let nullFileList = Array();
        let fileArray = {keys: Array(), values: Object()};
        let file_list = JSON.parse(atob($('input[name="_files"]').val()));
        let inline_file_list = Array();
        let namesWithImages = Object();
        for (let i = 0; i < file_list.length; i++) {
            let the_file_input = $('#' + file_list[i].replace(/(:|\.|\[|]|,|=|\/|")/g, '\\$1'))[0];
            let the_max_size = $(the_file_input).data('maximagesize');
            let the_image_type = $(the_file_input).data('imagetype');
            let hasImages = false;
            if (typeof the_max_size != 'undefined' || typeof the_image_type != 'undefined') {
                for (let j = 0; j < the_file_input.files.length; j++) {
                    let the_file = the_file_input.files[j];
                    if (the_file.type.match(/image.*/)) {
                        hasImages = true;
                    }
                }
            }
            if (hasImages || (daJsEmbed && the_file_input.files.length > 0)) {
                for (let j = 0; j < the_file_input.files.length; j++) {
                    let the_file = the_file_input.files[j];
                    filesToRead++;
                }
                inline_file_list.push(file_list[i]);
            } else if (the_file_input.files.length > 0) {
                newFileList.push(file_list[i]);
            } else {
                nullFileList.push(file_list[i]);
            }
            namesWithImages[file_list[i]] = hasImages;
        }
        if (inline_file_list.length > 0) {
            let originalFileList = atob($('input[name="_files"]').val())
            if (newFileList.length === 0 && nullFileList.length === 0) {
                $('input[name="_files"]').remove();
            } else {
                $('input[name="_files"]').val(btoa(JSON_stringify(newFileList.concat(nullFileList))));
            }
            for (let i = 0; i < inline_file_list.length; i++) {
                fileArray.keys.push(inline_file_list[i])
                fileArray.values[inline_file_list[i]] = Array()
                let fileInfoList = fileArray.values[inline_file_list[i]];
                let file_input = $('#' + inline_file_list[i].replace(/(:|\.|\[|\]|,|=|\/|\")/g, '\\$1'))[0];
                let max_size;
                let image_type;
                let image_mime_type;
                let this_has_images = false;
                if (namesWithImages[inline_file_list[i]]) {
                    this_has_images = true;
                    max_size = parseInt($(file_input).data('maximagesize'));
                    image_type = $(file_input).data('imagetype');
                    image_mime_type = null;
                    if (image_type) {
                        if (image_type === 'png') {
                            image_mime_type = 'image/png';
                        } else if (image_type === 'bmp') {
                            image_mime_type = 'image/bmp';
                        } else {
                            image_mime_type = 'image/jpeg';
                            image_type = 'jpg';
                        }
                    }
                }
                for (let j = 0; j < file_input.files.length; j++) {
                    let a_file = file_input.files[j];
                    let tempFunc = function (the_file, max_size, has_images) {
                        let reader = new FileReader();
                        let thisFileInfo = {name: the_file.name, size: the_file.size, type: the_file.type};
                        fileInfoList.push(thisFileInfo);
                        reader.onload = function () {
                            if (has_images && the_file.type.match(/image.*/) && !(the_file.type.indexOf('image/svg') == 0)) {
                                let convertedName = the_file.name;
                                let convertedType = the_file.type;
                                if (image_type) {
                                    let pos = the_file.name.lastIndexOf(".");
                                    convertedName = the_file.name.substr(0, pos < 0 ? the_file.name.length : pos) + "." + image_type;
                                    convertedType = image_mime_type;
                                    thisFileInfo.name = convertedName;
                                    thisFileInfo.type = convertedType;
                                }
                                let image = new Image();
                                image.onload = function (imageEvent) {
                                    let canvas = document.createElement('canvas'),
                                        width = image.width,
                                        height = image.height;
                                    if (width > height) {
                                        if (width > max_size) {
                                            height *= max_size / width;
                                            width = max_size;
                                        }
                                    } else {
                                        if (height > max_size) {
                                            width *= max_size / height;
                                            height = max_size;
                                        }
                                    }
                                    canvas.width = width;
                                    canvas.height = height;
                                    canvas.getContext('2d').drawImage(image, 0, 0, width, height);
                                    thisFileInfo['content'] = canvas.toDataURL(convertedType);
                                    filesRead++;
                                    if (filesRead >= filesToRead) {
                                        daResumeUploadSubmission(form, fileArray, inline_file_list, newFileList);
                                    }
                                };
                                image.src = reader.result;
                            } else {
                                thisFileInfo['content'] = reader.result;
                                filesRead++;
                                if (filesRead >= filesToRead) {
                                    daResumeUploadSubmission(form, fileArray, inline_file_list, newFileList);
                                }
                            }
                        };
                        reader.readAsDataURL(the_file);
                    };
                    tempFunc(a_file, max_size, this_has_images);
                    inline_succeeded = true;
                }
            }
        }
        if (newFileList.length !== 0) {
            do_iframe_upload = true;
        }
    }
    if (inline_succeeded) {
        return false;
    }
    if (do_iframe_upload) {
        $("#dauploadiframe").remove();
        let iframe = $('<iframe name="dauploadiframe" id="dauploadiframe" style="display: none"><\/iframe>');
        $(daTargetDiv).append(iframe);
        $(form).attr("target", "dauploadiframe");
        iframe.bind('load', function () {
            setTimeout(function () {
                try {
                    daProcessAjax($.parseJSON(daUnfakeHtmlResponse($("#dauploadiframe").contents().text())), form, 1);
                } catch (e) {
                    try {
                        daProcessAjax($.parseJSON($("#dauploadiframe").contents().text()), form, 1);
                    } catch (f) {
                        daShowErrorScreen(document.getElementById('dauploadiframe').contentWindow.document.body.innerHTML, f);
                    }
                }
            }, 0);
        });
        form.submit();
    } else {
        $.ajax({
            type: "POST",
            url: daInterviewUrl,
            data: $(form).serialize(),
            beforeSend: addCsrfHeader,
            xhrFields: {
                withCredentials: true
            },
            success: function (data) {
                setTimeout(function () {
                    daProcessAjax(data, form, 1);
                }, 0);
            },
            error: function (xhr, status, error) {
                setTimeout(function () {
                    daProcessAjaxError(xhr, status, error);
                }, 0);
            }
        });
    }
    return false;
}
function daSignatureSubmit(event) {
    $(this).find("input[name='ajax']").val(1);
    $.ajax({
        type: "POST",
        url: daInterviewUrl,
        data: $(this).serialize(),
        beforeSend: addCsrfHeader,
        xhrFields: {
            withCredentials: true
        },
        success: function (data) {
            setTimeout(function () {
                daProcessAjax(data, $(this), 1);
            }, 0);
        },
        error: function (xhr, status, error) {
            setTimeout(function () {
                daProcessAjaxError(xhr, status, error);
            }, 0);
        }
    });
    event.preventDefault();
    event.stopPropagation();
    return false;
}
function JSON_stringify(s) {
    let json = JSON.stringify(s);
    return json.replace(/[\u007f-\uffff]/g,
        function (c) {
            return '\\u' + ('0000' + c.charCodeAt(0).toString(16)).slice(-4);
        }
    );
}
function daResumeUploadSubmission(form, fileArray, inline_file_list, newFileList) {
    $('<input>').attr({
        type: 'hidden',
        name: '_files_inline',
        value: btoa(JSON_stringify(fileArray))
    }).appendTo($(form));
    for (let i = 0; i < inline_file_list.length; ++i) {
        document.getElementById(inline_file_list[i]).disabled = true;
    }
    if (newFileList.length > 0) {
        $("#dauploadiframe").remove();
        let iframe = $('<iframe name="dauploadiframe" id="dauploadiframe" style="display: none"><\/iframe>');
        $(daTargetDiv).append(iframe);
        $(form).attr("target", "dauploadiframe");
        iframe.bind('load', function () {
            setTimeout(function () {
                daProcessAjax($.parseJSON($("#dauploadiframe").contents().text()), form, 1);
            }, 0);
        });
        form.submit();
    } else {
        $.ajax({
            type: "POST",
            url: daInterviewUrl,
            data: $(form).serialize(),
            beforeSend: addCsrfHeader,
            xhrFields: {
                withCredentials: true
            },
            success: function (data) {
                setTimeout(function () {
                    daProcessAjax(data, form, 1);
                }, 0);
            },
            error: function (xhr, status, error) {
                setTimeout(function () {
                    daProcessAjaxError(xhr, status, error);
                }, 0);
            }
        });
    }
}
function daPushChanges() {
    //console.log("daPushChanges");
    if (daCheckinSeconds == 0 || daShowIfInProcess) {
        return true;
    }
    if (daCheckinInterval != null) {
        clearInterval(daCheckinInterval);
    }
    daCheckin();
    daCheckinInterval = setInterval(daCheckin, daCheckinSeconds);
    return true;
}
function daProcessAjaxError(xhr, status, error) {
    if (xhr.responseType === undefined || xhr.responseType === '' || xhr.responseType === 'text') {
        let theHtml = xhr.responseText;
        if (theHtml === undefined) {
            $(daTargetDiv).html("error");
        } else {
            theHtml = theHtml.replace(/<script[^>]*>[^<]*<\/script>/g, '');
            $(daTargetDiv).html(theHtml);
        }
        if (daJsEmbed) {
            $(daTargetDiv)[0].scrollTo(0, 1);
        } else {
            window.scrollTo(0, 1);
        }
    } else {
        console.log("daProcessAjaxError: response was not text");
    }
}
function daAddScriptToHead(src) {
    let head = document.getElementsByTagName("head")[0];
    let script = document.createElement("script");
    script.type = "text/javascript";
    script.src = src;
    script.async = true;
    script.defer = true;
    head.appendChild(script);
}
$(document).on('keydown', function (e) {
    if (e.which == 13) {
        if (daShowingHelp == 0) {
            let tag = $(document.activeElement).prop("tagName");
            if (tag != "INPUT" && tag != "TEXTAREA" && tag != "A" && tag != "LABEL" && tag != "BUTTON") {
                e.preventDefault();
                e.stopPropagation();
                if ($("#daform .da-field-buttons button").not('.danonsubmit').length === 1) {
                    $("#daform .da-field-buttons button").not('.danonsubmit').click();
                }
                return false;
            }
        }
        if ($(document.activeElement).hasClass("btn-file")) {
            e.preventDefault();
            e.stopPropagation();
            $(document.activeElement).find('input').click();
            return false;
        }
    }
});
function daShowErrorScreen(data, error) {
    console.log('daShowErrorScreen: ' + error);
    if ("activeElement" in document) {
        document.activeElement.blur();
    }
    $(daTargetDiv).html(data);
}
function daProcessAjax(data, form, doScroll, actionURL) {
    daInformedChanged = false;
    if (daDisable != null) {
        clearTimeout(daDisable);
    }
    daCsrf = data.csrf_token;
    if (data.question_data) {
        daQuestionData = data.question_data;
    }
    if (data.action == 'body') {
        {% if forceFullScreen %}
          if (data.steps > 1 && window != top) {
            top.location.href = location.href;
            return;
          }
        {% endif %}
        {{ forceFullScreen }}
        if ("activeElement" in document) {
            document.activeElement.blur();
        }
        $(daTargetDiv).html(data.body);
        let bodyClasses = $(daTargetDiv).parent()[0].className.split(/\s+/);
        let n = bodyClasses.length;
        while (n--) {
            if (bodyClasses[n] == 'dabody' || bodyClasses[n] == 'dasignature' || bodyClasses[n].indexOf('question-') == 0) {
                $(daTargetDiv).parent().removeClass(bodyClasses[n]);
            }
        }
        $(daTargetDiv).parent().addClass(data.bodyclass);
        $("meta[name=viewport]").attr('content', "width=device-width, initial-scale=1");
        daDoAction = data.do_action;
        //daNextAction = data.next_action;
        daChatAvailable = data.livehelp.availability;
        daChatMode = data.livehelp.mode;
        daChatRoles = data.livehelp.roles;
        daChatPartnerRoles = data.livehelp.partner_roles;
        daSteps = data.steps;
        //console.log("daProcessAjax: pushing " + daSteps);
        if (!daJsEmbed && !daIframeEmbed) {
            if (history.state != null && daSteps > history.state.steps) {
                history.pushState({steps: daSteps}, data.browser_title + " - page " + daSteps, daLocationBar + {{ page_sep | tojson }} +daSteps);
            } else {
                history.replaceState({steps: daSteps}, "", daLocationBar + {{ page_sep | tojson }} +daSteps);
            }
        }
        daAllowGoingBack = data.allow_going_back;
        daQuestionID = data.id_dict;
        daMessageLog = data.message_log;
        daInitialize(doScroll);
        let tempDiv = document.createElement('div');
        tempDiv.innerHTML = data.extra_scripts;
        let scripts = tempDiv.getElementsByTagName('script');
        for (let i = 0; i < scripts.length; i++) {
            //console.log("Found one script");
            if (scripts[i].src != "") {
                //console.log("Added script to head");
                daAddScriptToHead(scripts[i].src);
            } else {
                daGlobalEval(scripts[i].innerHTML);
            }
        }
        $(".da-group-has-error").each(function () {
            if ($(this).is(":visible")) {
                if (daJsEmbed) {
                    let scrollToTarget = $(this).position().top - 60;
                    setTimeout(function () {
                        $(daTargetDiv).animate({scrollTop: scrollToTarget}, 1000);
                    }, 100);
                } else {
                    let scrollToTarget = $(this).offset().top - 60;
                    setTimeout(function () {
                        $(daTargetDiv).parent().parent().animate({scrollTop: scrollToTarget}, 1000);
                    }, 100);
                }
                return false;
            }
        });
        for (let i = 0; i < data.extra_css.length; i++) {
            $("head").append(data.extra_css[i]);
        }
        document.title = data.browser_title;
        if ($("html").attr("lang") != data.lang) {
            $("html").attr("lang", data.lang);
        }
        if (daReloader != null) {
            clearTimeout(daReloader);
        }
        if (data.reload_after != null && data.reload_after > 0) {
            //daReloader = setTimeout(function(){location.reload();}, data.reload_after);
            daReloader = setTimeout(function () {
                daRefreshSubmit();
            }, data.reload_after);
        }
        daUpdateHeight();
    } else if (data.action === 'redirect') {
        if (daSpinnerTimeout != null) {
            clearTimeout(daSpinnerTimeout);
            daSpinnerTimeout = null;
        }
        if (daShowingSpinner) {
            daHideSpinner();
        }
        window.location = data.url;
    } else if (data.action === 'refresh') {
        daRefreshSubmit();
    } else if (data.action === 'reload') {
        location.reload(true);
    } else if (data.action === 'resubmit') {
        if (form == null) {
            window.location = actionURL;
        }
        $("input[name='ajax']").remove();
        if (daSubmitter != null) {
            let input = $("<input>")
                .attr("type", "hidden")
                .attr("name", daSubmitter.name).val(daSubmitter.value);
            $(form).append($(input));
        }
        form.submit();
    }
}
function daEmbeddedJs(e) {
    //console.log("using embedded js");
    let data = decodeURIComponent($(this).data('js'));
    daGlobalEval(data);
    e.preventDefault();
    return false;
}
function daEmbeddedAction(e) {
    if ($(this).hasClass("daremovebutton")) {
        if (confirm({{ word("Are you sure you want to delete this item?") | tojson }})) {
            return true;
        }
        e.preventDefault();
        $(this).blur();
        return false;
    }
    let actionData = decodeURIComponent($(this).data('embaction'));
    let theURL = $(this).attr("href");
    $.ajax({
        type: "POST",
        url: daInterviewUrl,
        data: $.param({_action: actionData, csrf_token: daCsrf, ajax: 1}),
        beforeSend: addCsrfHeader,
        xhrFields: {
            withCredentials: true
        },
        success: function (data) {
            setTimeout(function () {
                daProcessAjax(data, null, 1, theURL);
            }, 0);
        },
        error: function (xhr, status, error) {
            setTimeout(function () {
                daProcessAjaxError(xhr, status, error);
            }, 0);
        },
        dataType: 'json'
    });
    daSpinnerTimeout = setTimeout(daShowSpinner, 1000);
    e.preventDefault();
    return false;
}
function daReviewAction(e) {
    //action_perform_with_next($(this).data('action'), null, daNextAction);
    let info = $.parseJSON(atob($(this).data('action')));
    da_action_perform(info['action'], info['arguments']);
    e.preventDefault();
    return false;
}
function daRingChat() {
    daChatStatus = 'ringing';
    daPushChanges();
}
function daTurnOnChat() {
    //console.log("Publishing from daTurnOnChat");
    $("#daChatOnButton").addClass("dainvisible");
    $("#daChatBox").removeClass("dainvisible");
    $("#daCorrespondence").html('');
    for (let i = 0; i < daChatHistory.length; i++) {
        daPublishMessage(daChatHistory[i]);
    }
    daScrollChatFast();
    $("#daMessage").prop('disabled', false);
    if (daShowingHelp) {
        $("#daMessage").focus();
    }
}
function daCloseChat() {
    //console.log('daCloseChat');
    daChatStatus = 'hangup';
    daPushChanges();
    if (daSocket != null && daSocket.connected) {
        daSocket.disconnect();
    }
}
// function daTurnOffChat(){
//   $("#daChatOnButton").removeClass("dainvisible");
//   $("#daChatBox").addClass("dainvisible");
//   //daCloseSocket();
//   $("#daMessage").prop('disabled', true);
//   $("#daSend").unbind();
//   //daStartCheckingIn();
// }
function daDisplayChat() {
    if (daChatStatus === 'off' || daChatStatus === 'observeonly') {
        $("#daChatBox").addClass("dainvisible");
        $("#daChatAvailable").addClass("dainvisible");
        $("#daChatOnButton").addClass("dainvisible");
    } else {
        if (daChatStatus === 'waiting') {
            if (daChatPartnersAvailable > 0) {
                $("#daChatBox").removeClass("dainvisible");
            }
        } else {
            $("#daChatBox").removeClass("dainvisible");
        }
    }
    if (daChatStatus === 'waiting') {
        //console.log("I see waiting")
        if (daChatHistory.length > 0) {
            $("#daChatAvailable a i").removeClass("da-chat-active");
            $("#daChatAvailable a i").addClass("da-chat-inactive");
            $("#daChatAvailable").removeClass("dainvisible");
        } else {
            $("#daChatAvailable a i").removeClass("da-chat-active");
            $("#daChatAvailable a i").removeClass("da-chat-inactive");
            $("#daChatAvailable").addClass("dainvisible");
        }
        $("#daChatOnButton").addClass("dainvisible");
        $("#daChatOffButton").addClass("dainvisible");
        $("#daMessage").prop('disabled', true);
        $("#daSend").prop('disabled', true);
    }
    if (daChatStatus === 'standby' || daChatStatus === 'ready') {
        //console.log("I see standby")
        $("#daChatAvailable").removeClass("dainvisible");
        $("#daChatAvailable a i").removeClass("da-chat-inactive");
        $("#daChatAvailable a i").addClass("da-chat-active");
        $("#daChatOnButton").removeClass("dainvisible");
        $("#daChatOffButton").addClass("dainvisible");
        $("#daMessage").prop('disabled', true);
        $("#daSend").prop('disabled', true);
        daInformAbout('chat');
    }
    if (daChatStatus === 'on') {
        $("#daChatAvailable").removeClass("dainvisible");
        $("#daChatAvailable a i").removeClass("da-chat-inactive");
        $("#daChatAvailable a i").addClass("da-chat-active");
        $("#daChatOnButton").addClass("dainvisible");
        $("#daChatOffButton").removeClass("dainvisible");
        $("#daMessage").prop('disabled', false);
        if (daShowingHelp) {
            $("#daMessage").focus();
        }
        $("#daSend").prop('disabled', false);
        daInformAbout('chat');
    }
    hideTablist();
}
function daChatLogCallback(data) {
    if (data.action && data.action === 'reload') {
        location.reload(true);
    }
    //console.log("daChatLogCallback: success is " + data.success);
    if (data.success) {
        $("#daCorrespondence").html('');
        daChatHistory = [];
        let messages = data.messages;
        for (let i = 0; i < messages.length; ++i) {
            daChatHistory.push(messages[i]);
            daPublishMessage(messages[i]);
        }
        daDisplayChat();
        daScrollChatFast();
    }
}
function daRefreshSubmit() {
    $.ajax({
        type: "POST",
        url: daInterviewUrl,
        data: 'csrf_token=' + daCsrf + '&ajax=1',
        beforeSend: addCsrfHeader,
        xhrFields: {
            withCredentials: true
        },
        success: function (data) {
            setTimeout(function () {
                daProcessAjax(data, $("#daform"), 0);
            }, 0);
        },
        error: function (xhr, status, error) {
            setTimeout(function () {
                daProcessAjaxError(xhr, status, error);
            }, 0);
        }
    });
}
function daResetCheckinCode() {
    daCheckinCode = Math.random();
}
function daCheckinCallback(data) {
    if (data.action && data.action === 'reload') {
        location.reload(true);
    }
    daCheckingIn = 0;
    //console.log("daCheckinCallback: success is " + data.success);
    if (data.checkin_code != daCheckinCode) {
        console.log("Ignoring checkincallback because code is wrong");
        return;
    }
    if (data.success) {
        if (data.commands.length > 0) {
            for (let i = 0; i < data.commands.length; ++i) {
                let command = data.commands[i];
                if (command.extra == 'flash') {
                    if (!$("#daflash").length) {
                        $(daTargetDiv).append(daSprintf(daNotificationContainer, ""));
                    }
                    $("#daflash").append(daSprintf(daNotificationMessage, "info", command.value));
                    //console.log("command is " + command.value);
                } else if (command.extra == 'refresh') {
                    daRefreshSubmit();
                } else if (command.extra == 'javascript') {
                    //console.log("I should eval" + command.value);
                    daGlobalEval(command.value);
                } else if (command.extra == 'fields') {
                    for (let key in command.value) {
                        if (command.value.hasOwnProperty(key)) {
                            daSetField(key, command.value[key]);
                        }
                    }
                } else if (command.extra == 'backgroundresponse') {
                    let assignments = Array();
                    if (command.value.hasOwnProperty('target') && command.value.hasOwnProperty('content')) {
                        assignments.push({target: command.value.target, content: command.value.content});
                    }
                    if (Array.isArray(command.value)) {
                        for (i = 0; i < command.value.length; ++i) {
                            let possible_assignment = command.value[i];
                            if (possible_assignment.hasOwnProperty('target') && possible_assignment.hasOwnProperty('content')) {
                                assignments.push({
                                    target: possible_assignment.target,
                                    content: possible_assignment.content
                                });
                            }
                        }
                    }
                    for (i = 0; i < assignments.length; ++i) {
                        let assignment = assignments[i];
                        $('.datarget' + assignment.target.replace(/[^A-Za-z0-9\_]/g)).prop('innerHTML', assignment.content);
                    }
                    //console.log("Triggering daCheckIn");
                    $(document).trigger('daCheckIn', [command.action, command.value]);
                }
            }
            // setTimeout(function(){
            //   $("#daflash .daalert-interlocutory").hide(300, function(){
            //     $(self).remove();
            //   });
            // }, 5000);
        }
        oldDaChatStatus = daChatStatus;
        //console.log("daCheckinCallback: from " + daChatStatus + " to " + data.chat_status);
        if (data.phone == null) {
            $("#daPhoneMessage").addClass("dainvisible");
            $("#daPhoneMessage p").html('');
            $("#daPhoneAvailable").addClass("dainvisible");
            daPhoneAvailable = false;
        } else {
            $("#daPhoneMessage").removeClass("dainvisible");
            $("#daPhoneMessage p").html(data.phone);
            $("#daPhoneAvailable").removeClass("dainvisible");
            daPhoneAvailable = true;
            daInformAbout('phone');
        }
        let statusChanged;
        if (daChatStatus === data.chat_status) {
            statusChanged = false;
        } else {
            statusChanged = true;
        }
        if (statusChanged) {
            daChatStatus = data.chat_status;
            daDisplayChat();
            if (daChatStatus === 'ready') {
                //console.log("calling initialize socket because ready");
                daInitializeSocket();
            }
        }
        daChatPartnersAvailable = 0;
        if (daChatMode == 'peer' || daChatMode == 'peerhelp') {
            daChatPartnersAvailable += data.num_peers;
            if (data.num_peers == 1) {
                $("#dapeerMessage").html('<span class="badge bg-info">' + data.num_peers + ' ' + {{ word("other user") | tojson }} +'<\/span>');
            } else {
                $("#dapeerMessage").html('<span class="badge bg-info">' + data.num_peers + ' ' + {{ word("other user") | tojson }} +'<\/span>');
            }
            $("#dapeerMessage").removeClass("dainvisible");
        } else {
            $("#dapeerMessage").addClass("dainvisible");
        }
        if (daChatMode == 'peerhelp' || daChatMode == 'help') {
            if (data.help_available == 1) {
                $("#dapeerHelpMessage").html('<span class="badge bg-primary">' + data.help_available + ' ' + {{ word("operator") | tojson }} +'<\/span>');
            } else {
                $("#dapeerHelpMessage").html('<span class="badge bg-primary">' + data.help_available + ' ' + {{ word("operators") | tojson }} +'<\/span>');
            }
            $("#dapeerHelpMessage").removeClass("dainvisible");
        } else {
            $("#dapeerHelpMessage").addClass("dainvisible");
        }
        if (daBeingControlled) {
            if (!data.observerControl) {
                daBeingControlled = false;
                //console.log("Hiding control 1");
                daHideControl();
                if (daChatStatus !== 'on') {
                    if (daSocket != null && daSocket.connected) {
                        //console.log('Terminating interview socket because control is over');
                        daSocket.emit('terminate');
                    }
                }
            }
        } else {
            if (data.observerControl) {
                daBeingControlled = true;
                daInitializeSocket();
            }
        }
    }
    hideTablist();
}
function daCheckoutCallback(data) {
}
function daCheckin() {
    //console.log("daCheckin");
    daCheckingIn += 1;
    //if (daCheckingIn > 1 && !(daCheckingIn % 3)){
    if (daCheckingIn > 1) {
        //console.log("daCheckin: request already pending, not re-sending");
        return;
    }
    let datastring;
    const daForm = $("#daform");
    if ((daChatStatus !== 'off') && daForm.length > 0 && !daBeingControlled) {
        if (daDoAction != null) {
            datastring = $.param({
                action: 'checkin',
                chatstatus: daChatStatus,
                chatmode: daChatMode,
                csrf_token: daCsrf,
                checkinCode: daCheckinCode,
                parameters: daFormAsJSON(),
                raw_parameters: JSON.stringify(daForm.serializeArray()),
                do_action: daDoAction,
                ajax: '1'
            });
        } else {
            datastring = $.param({
                action: 'checkin',
                chatstatus: daChatStatus,
                chatmode: daChatMode,
                csrf_token: daCsrf,
                checkinCode: daCheckinCode,
                parameters: daFormAsJSON(),
                raw_parameters: JSON.stringify(daForm.serializeArray()),
                ajax: '1'
            });
        }
    } else {
        if (daDoAction != null) {
            datastring = $.param({
                action: 'checkin',
                chatstatus: daChatStatus,
                chatmode: daChatMode,
                csrf_token: daCsrf,
                checkinCode: daCheckinCode,
                do_action: daDoAction,
                parameters: daFormAsJSON(),
                ajax: '1'
            });
        } else {
            datastring = $.param({
                action: 'checkin',
                chatstatus: daChatStatus,
                chatmode: daChatMode,
                csrf_token: daCsrf,
                checkinCode: daCheckinCode,
                ajax: '1'
            });
        }
    }
    //console.log("Doing checkin with " + daChatStatus);
    $.ajax({
        type: 'POST',
        url: '{{ url_for('checkin', i=yaml_filename) }}',
        beforeSend: addCsrfHeader,
        xhrFields: {
            withCredentials: true
        },
        data: datastring,
        success: daCheckinCallback,
        dataType: 'json'
    });
    return true;
}
function daCheckout() {
    $.ajax({
        type: 'POST',
        url: '{{ url_for("auth.checkout", i=yaml_filename) }}',
        beforeSend: addCsrfHeader,
        xhrFields: {
            withCredentials: true
        },
        data: 'csrf_token=' + daCsrf + '&ajax=1&action=checkout',
        success: daCheckoutCallback,
        dataType: 'json'
    });
    return true;
}
function daStopCheckingIn() {
    daCheckout();
    if (daCheckinInterval != null) {
        clearInterval(daCheckinInterval);
    }
}
function daShowSpinner() {
    if ($("#daquestion").length > 0) {
        $('<div id="daSpinner" class="da-spinner-container da-top-for-navbar"><div class="container"><div class="row"><div class="col text-center"><span class="da-spinner"><i class="fas fa-spinner fa-spin"><\/i><\/span><\/div><\/div><\/div><\/div>').appendTo(daTargetDiv);
    } else {
        let newSpan = document.createElement('span');
        let newI = document.createElement('i');
        $(newI).addClass("fas fa-spinner fa-spin");
        $(newI).appendTo(newSpan);
        $(newSpan).attr("id", "daSpinner");
        $(newSpan).addClass("da-sig-spinner da-top-for-navbar");
        $(newSpan).appendTo("#dasigtoppart");
    }
    daShowingSpinner = true;
}
function daHideSpinner() {
    $("#daSpinner").remove();
    daShowingSpinner = false;
    daSpinnerTimeout = null;
}
function daAdjustInputWidth(e) {
    let contents = $(this).val();
    let leftBracket = new RegExp('<', 'g');
    let rightBracket = new RegExp('>', 'g');
    contents = contents.replace(/&/g, '&amp;').replace(leftBracket, '&lt;').replace(rightBracket, '&gt;').replace(/ /g, '&nbsp;');
    $('<span class="dainput-embedded" id="dawidth">').html(contents).appendTo('#daquestion');
    $("#dawidth").css('min-width', $(this).css('min-width'));
    $("#dawidth").css('background-color', $(daTargetDiv).css('background-color'));
    $("#dawidth").css('color', $(daTargetDiv).css('background-color'));
    $(this).width($('#dawidth').width() + 16);
    setTimeout(function () {
        $("#dawidth").remove();
    }, 0);
}
function daShowNotifications() {
    let n = daMessageLog.length;
    for (let i = 0; i < n; i++) {
        let message = daMessageLog[i];
        if (message.priority == 'console') {
            console.log(message.message);
        } else if (message.priority == 'javascript') {
            daGlobalEval(message.message);
        } else if (message.priority == 'success' || message.priority == 'warning' || message.priority == 'danger' || message.priority == 'secondary' || message.priority == 'info' || message.priority == 'secondary' || message.priority == 'dark' || message.priority == 'light' || message.priority == 'primary') {
            da_flash(message.message, message.priority);
        } else {
            da_flash(message.message, 'info');
        }
    }
}
function daIgnoreAllButTab(event) {
    event = event || window.event;
    let code = event.keyCode;
    if (code != 9) {
        if (code == 13) {
            $(event.target).parents(".file-caption-main").find("input.dafile").click();
        }
        event.preventDefault();
        return false;
    }
}
function daDisableIfNotHidden(query, value) {
    $(query).each(function () {
        let showIfParent = $(this).parents('.dashowif,.dajsshowif');
        if (!(showIfParent.length && ($(showIfParent[0]).data('isVisible') == '0' || !$(showIfParent[0]).is(":visible")))) {
            if ($(this).hasClass('combobox')) {
                if (value) {
                    daComboBoxes[$(this).attr('id')].disable();
                } else {
                    daComboBoxes[$(this).attr('id')].enable();
                }
            } else {
                $(this).prop("disabled", value);
            }
        }
    });
}
function daShowIfCompare(theVal, showIfVal) {
    if (typeof theVal == 'string' && theVal.match(/^-?\d+\.\d+$/)) {
        theVal = parseFloat(theVal);
    } else if (typeof theVal == 'string' && theVal.match(/^-?\d+$/)) {
        theVal = parseInt(theVal);
    }
    if (typeof showIfVal == 'string' && showIfVal.match(/^-?\d+\.\d+$/)) {
        showIfVal = parseFloat(showIfVal);
    } else if (typeof showIfVal == 'string' && showIfVal.match(/^-?\d+$/)) {
        showIfVal = parseInt(showIfVal);
    }
    if (typeof theVal == 'string' || typeof showIfVal == 'string') {
        if (String(showIfVal) == 'None' && String(theVal) == '') {
            return true;
        }
        return (String(theVal) == String(showIfVal));
    }
    return (theVal == showIfVal);
}
function rationalizeListCollect() {
    let finalNum = $(".dacollectextraheader").last().data('collectnum');
    let num = $(".dacollectextraheader:visible").last().data('collectnum');
    if (parseInt(num) < parseInt(finalNum)) {
        if ($('div.dacollectextraheader[data-collectnum="' + num + '"]').find(".dacollectadd").hasClass('dainvisible')) {
            $('div.dacollectextraheader[data-collectnum="' + (num + 1) + '"]').show('fast');
        }
    }
    let n = parseInt(finalNum);
    let firstNum = parseInt($(".dacollectextraheader").first().data('collectnum'));
    while (n-- > firstNum) {
        if ($('div.dacollectextraheader[data-collectnum="' + (n + 1) + '"]:visible').length > 0) {
            if (!$('div.dacollectextraheader[data-collectnum="' + (n + 1) + '"]').find(".dacollectadd").hasClass('dainvisible') && $('div.dacollectextraheader[data-collectnum="' + n + '"]').find(".dacollectremove").hasClass('dainvisible')) {
                $('div.dacollectextraheader[data-collectnum="' + (n + 1) + '"]').hide();
            }
        }
    }
    n = parseInt(finalNum);
    let seenAddAnother = false;
    while (n-- > firstNum) {
        if ($('div.dacollectextraheader[data-collectnum="' + (n + 1) + '"]:visible').length > 0) {
            if (!$('div.dacollectextraheader[data-collectnum="' + (n + 1) + '"]').find(".dacollectadd").hasClass('dainvisible')) {
                seenAddAnother = true;
            }
            let current = $('div.dacollectextraheader[data-collectnum="' + n + '"]');
            if (seenAddAnother && !$(current).find(".dacollectadd").hasClass('dainvisible')) {
                $(current).find(".dacollectadd").addClass('dainvisible');
                $(current).find(".dacollectunremove").removeClass('dainvisible');
            }
        }
    }
}
function daFetchAjax(elem, cb, doShow) {
    let wordStart = $(elem).val();
    if (wordStart.length < parseInt(cb.$source.data('trig'))) {
        if (cb.shown) {
            cb.hide();
        }
        return;
    }
    if (daFetchAjaxTimeout != null && daFetchAjaxTimeoutRunning) {
        daFetchAjaxTimeoutFetchAfter = true;
        return;
    }
    if (doShow) {
        daFetchAjaxTimeout = setTimeout(function () {
            daFetchAjaxTimeoutRunning = false;
            if (daFetchAjaxTimeoutFetchAfter) {
                daFetchAjax(elem, cb, doShow);
                daFetchAjaxTimeoutFetchAfter = false;
            }
        }, 2000);
        daFetchAjaxTimeoutRunning = true;
        daFetchAjaxTimeoutFetchAfter = false;
    }
    da_action_call(cb.$source.data('action'), {wordstart: wordStart}, function (data) {
        wordStart = $(elem).val();
        if (typeof data == "object") {
            let upperWordStart = wordStart.toUpperCase()
            cb.$source.empty();
            let emptyItem = $("<option>");
            emptyItem.val("");
            emptyItem.text("");
            cb.$source.append(emptyItem);
            let notYetSelected = true;
            let selectedValue = null;
            if (Array.isArray(data)) {
                for (let i = 0; i < data.length; ++i) {
                    if (Array.isArray(data[i])) {
                        if (data[i].length >= 2) {
                            let item = $("<option>");
                            if (notYetSelected && ((doShow && data[i][1].toString() === wordStart) || data[i][0].toString() === wordStart)) {
                                item.prop('selected', true);
                                notYetSelected = false;
                                selectedValue = data[i][1]
                            }
                            item.text(data[i][1]);
                            item.val(data[i][0]);
                            cb.$source.append(item);
                        } else if (data[i].length === 1) {
                            let item = $("<option>");
                            if (notYetSelected && ((doShow && data[i][0].toString() === wordStart) || data[i][0].toString() === wordStart)) {
                                item.prop('selected', true);
                                notYetSelected = false;
                                selectedValue = data[i][0]
                            }
                            item.text(data[i][0]);
                            item.val(data[i][0]);
                            cb.$source.append(item);
                        }
                    } else if (typeof data[i] == "object") {
                        for (let key in data[i]) {
                            if (data[i].hasOwnProperty(key)) {
                                let item = $("<option>");
                                if (notYetSelected && ((doShow && key.toString() === wordStart) || key.toString() === wordStart)) {
                                    item.prop('selected', true);
                                    notYetSelected = false;
                                    selectedValue = data[i][key];
                                }
                                item.text(data[i][key]);
                                item.val(key);
                                cb.$source.append(item);
                            }
                        }
                    } else {
                        let item = $("<option>");
                        if (notYetSelected && ((doShow && data[i].toString().toUpperCase() == upperWordStart) || data[i].toString() === wordStart)) {
                            item.prop('selected', true);
                            notYetSelected = false;
                            selectedValue = data[i];
                        }
                        item.text(data[i]);
                        item.val(data[i]);
                        cb.$source.append(item);
                    }
                }
            } else if (typeof data == "object") {
                let keyList = Array();
                for (let key in data) {
                    if (data.hasOwnProperty(key)) {
                        keyList.push(key);
                    }
                }
                keyList = keyList.sort();
                for (let i = 0; i < keyList.length; ++i) {
                    let item = $("<option>");
                    if (notYetSelected && ((doShow && keyList[i].toString().toUpperCase() == upperWordStart) || keyList[i].toString() === wordStart)) {
                        item.prop('selected', true);
                        notYetSelected = false;
                        selectedValue = data[keyList[i]];
                    }
                    item.text(data[keyList[i]]);
                    item.val(keyList[i]);
                    cb.$source.append(item);
                }
            }
            if (doShow) {
                cb.refresh();
                cb.clearTarget();
                cb.$target.val(cb.$element.val());
                cb.lookup();
            } else {
                if (!notYetSelected) {
                    cb.$element.val(selectedValue);
                }
            }
        }
    });
}
function daInitialize(doScroll) {
    daResetCheckinCode();
    daComboBoxes = Object();
    if (daSpinnerTimeout != null) {
        clearTimeout(daSpinnerTimeout);
        daSpinnerTimeout = null;
    }
    if (daShowingSpinner) {
        daHideSpinner();
    }
    daNotYetScrolled = true;
    // $(".dahelptrigger").click(function(e) {
    //   e.preventDefault();
    //   $(this).tab('show');
    // });
    $(".datableup,.databledown").click(function (e) {
        e.preventDefault();
        $(this).blur();
        let row = $(this).parents("tr").first();
        if ($(this).is(".datableup")) {
            let prev = row.prev();
            if (prev.length === 0) {
                return false;
            }
            row.addClass("datablehighlighted");
            setTimeout(function () {
                row.insertBefore(prev);
            }, 200);
        } else {
            let next = row.next();
            if (next.length === 0) {
                return false;
            }
            row.addClass("datablehighlighted");
            setTimeout(function () {
                row.insertAfter(row.next());
            }, 200);
        }
        setTimeout(function () {
            row.removeClass("datablehighlighted");
        }, 1000);
        return false;
    });
    const collectExtra = $(".dacollectextra");
    collectExtra.find('input, textarea, select').prop("disabled", true);
    collectExtra.find('input.combobox').each(function () {
        daComboBoxes[$(this).attr('id')].disable();
    });
    $("#da-extra-collect").on('click', function () {
        $("<input>").attr({
            type: 'hidden',
            name: '_collect',
            value: $(this).val()
        }).appendTo($("#daform"));
        $("#daform").submit();
        event.preventDefault();
        return false;
    });
    $(".dacollectadd").on('click', function (e) {
        e.preventDefault();
        if ($("#daform").valid()) {
            let num = $(this).parent().parent().data('collectnum');
            $('div[data-collectnum="' + num + '"]').show('fast');
            $('div[data-collectnum="' + num + '"]').find('input, textarea, select').prop("disabled", false);
            $('div[data-collectnum="' + num + '"]').find('input.combobox').each(function () {
                daComboBoxes[$(this).attr('id')].enable();
            });
            $(this).parent().find("button.dacollectremove").removeClass("dainvisible");
            $(this).parent().find("span.dacollectnum").removeClass("dainvisible");
            $(this).addClass("dainvisible");
            $(".da-first-delete").removeClass("dainvisible");
            rationalizeListCollect();
            let elem = $('div[data-collectnum="' + num + '"]').find('input, textarea, select').first();
            if ($(elem).visible()) {
                $(elem).focus();
            }
        }
        return false;
    });
    $("#dasigform").on('submit', daSignatureSubmit);
    $(".dacollectremove").on('click', function (e) {
        e.preventDefault();
        let num = $(this).parent().parent().data('collectnum');
        $('div[data-collectnum="' + num + '"]:not(.dacollectextraheader, .dacollectheader, .dacollectfirstheader)').hide('fast');
        $('div[data-collectnum="' + num + '"]').find('input, textarea, select').prop("disabled", true);
        $('div[data-collectnum="' + num + '"]').find('input.combobox').each(function () {
            daComboBoxes[$(this).attr('id')].disable();
        });
        $(this).parent().find("button.dacollectadd").removeClass("dainvisible");
        $(this).parent().find("span.dacollectnum").addClass("dainvisible");
        $(this).addClass("dainvisible");
        rationalizeListCollect();
        return false;
    });
    $(".dacollectremoveexisting").on('click', function (e) {
        e.preventDefault();
        let num = $(this).parent().parent().data('collectnum');
        $('div[data-collectnum="' + num + '"]:not(.dacollectextraheader, .dacollectheader, .dacollectfirstheader)').hide('fast');
        $('div[data-collectnum="' + num + '"]').find('input, textarea, select').prop("disabled", true);
        $('div[data-collectnum="' + num + '"]').find('input.combobox').each(function () {
            daComboBoxes[$(this).attr('id')].disable();
        });
        $(this).parent().find("button.dacollectunremove").removeClass("dainvisible");
        $(this).parent().find("span.dacollectremoved").removeClass("dainvisible");
        $(this).addClass("dainvisible");
        rationalizeListCollect();
        return false;
    });
    $(".dacollectunremove").on('click', function (e) {
        e.preventDefault();
        let num = $(this).parent().parent().data('collectnum');
        $('div[data-collectnum="' + num + '"]').show('fast');
        $('div[data-collectnum="' + num + '"]').find('input, textarea, select').prop("disabled", false);
        $('div[data-collectnum="' + num + '"]').find('input.combobox').each(function () {
            daComboBoxes[$(this).attr('id')].enable();
        });
        $(this).parent().find("button.dacollectremoveexisting").removeClass("dainvisible");
        $(this).parent().find("button.dacollectremove").removeClass("dainvisible");
        $(this).parent().find("span.dacollectnum").removeClass("dainvisible");
        $(this).parent().find("span.dacollectremoved").addClass("dainvisible");
        $(this).addClass("dainvisible");
        rationalizeListCollect();
        return false;
    });
    //$('#daquestionlabel').click(function(e) {
    //  e.preventDefault();
    //  $(this).tab('show');
    //});
    //$('#dapagetitle').click(function(e) {
    //  if ($(this).prop('href') == '#'){
    //    e.preventDefault();
    //    //$('#daquestionlabel').tab('show');
    //  }
    //});
    $('select.damultiselect').each(function () {
        let varname = atob($(this).data('varname'));
        let theSelect = this;
        $(this).find('option').each(function () {
            let theVal = atob($(this).data('valname'));
            let key = varname + '["' + theVal + '"]';
            if (!daVarLookupSelect[key]) {
                daVarLookupSelect[key] = [];
            }
            daVarLookupSelect[key].push({'select': theSelect, 'option': this});
            key = varname + "['" + theVal + "']"
            if (!daVarLookupSelect[key]) {
                daVarLookupSelect[key] = [];
            }
            daVarLookupSelect[key].push({'select': theSelect, 'option': this});
        });
    })
    $('.dacurrency').each(function () {
        let theVal = $(this).val().toString();
        if (theVal.indexOf('.') >= 0 || theVal.indexOf(',') >= 0) {
            let num = parseFloat(theVal);
            let cleanNum = num.toFixed({{ daconfig.get('currency decimal places', 2) }});
            $(this).val(cleanNum);
        }
    });
    $('.dacurrency').on('blur', function () {
        let theVal = $(this).val().toString();
        if (theVal.indexOf('.') >= 0 || theVal.indexOf(',') >= 0) {
            let num = parseFloat(theVal);
            let cleanNum = num.toFixed({{ daconfig.get('currency decimal places', 2) }});
            if (cleanNum != 'NaN') {
                $(this).val(cleanNum);
            }
        }
    });
    // iOS will truncate text in `select` options. Adding an empty optgroup fixes that
    if (navigator.userAgent.match(/(iPad|iPhone|iPod touch);/i)) {
        let selects = document.querySelectorAll("select");
        for (let i = 0; i < selects.length; i++) {
            selects[i].appendChild(document.createElement("optgroup"));
        }
    }
    $(".da-to-labelauty").labelauty({class: "labelauty da-active-invisible dafullwidth"});
    $(".da-to-labelauty-icon").labelauty({label: false});
    $("button").on('click', function () {
        daWhichButton = this;
        return true;
    });
    $('#dasource').on('shown.bs.collapse', function (e) {
        if (daJsEmbed) {
            let scrollTarget = $("#dasource").first().position().top - 60;
            $(daTargetDiv).animate({
                scrollTop: scrollTarget
            }, 1000);
        } else {
            let scrollTarget = $("#dasource").first().offset().top - 60;
            $("html, body").animate({
                scrollTop: scrollTarget
            }, 1000);
        }
    });
    $('button[data-bs-target="#dahelp"]').on('shown.bs.tab', function (e) {
        daShowingHelp = 1;
        if (daNotYetScrolled) {
            daScrollChatFast();
            daNotYetScrolled = false;
        }
        {{ debug_readability_help }}
    });
    $('button[data-bs-target="#daquestion"]').on('shown.bs.tab', function (e) {
        daShowingHelp = 0;
        {{ debug_readability_question }}
    });
    $("input.danota-checkbox").click(function () {
        $(this).parent().find('input.danon-nota-checkbox').each(function () {
            let existing_val = $(this).prop('checked');
            $(this).prop('checked', false);
            if (existing_val != false) {
                $(this).trigger('change');
            }
        });
    });
    $("input.danon-nota-checkbox").click(function () {
        $(this).parent().find('input.danota-checkbox').each(function () {
            let existing_val = $(this).prop('checked');
            $(this).prop('checked', false);
            if (existing_val != false) {
                $(this).trigger('change');
            }
        });
    });
    $("input.dafile").fileinput({theme: "fas", language: document.documentElement.lang});
    $('select.combobox').combobox();
    $('select.da-ajax-combobox').combobox({clearIfNoMatch: true});
    $('input.da-ajax-combobox').each(function () {
        let cb = daComboBoxes[$(this).attr("id")];
        daFetchAjax(this, cb, false);
        $(this).on('keyup', function (e) {
            switch (e.keyCode) {
                case 40:
                case 39: // right arrow
                case 38: // up arrow
                case 37: // left arrow
                case 36: // home
                case 35: // end
                case 16: // shift
                case 17: // ctrl
                case 9:  // tab
                case 13: // enter
                case 27: // escape
                case 18: // alt
                    return;
            }
            daFetchAjax(this, cb, true);
            daFetchAcceptIncoming = true;
            e.preventDefault();
            return false;
        });
    });
    $("#daemailform").validate({
        'submitHandler': daValidationHandler,
        'rules': {
            '_attachment_email_address': {
                'minlength': 1, 'required': true, 'email': true
            }
        },
        'messages': {
            '_attachment_email_address': {
                'required': {{ word("An e-mail address is required.") | tojson }},
                'email': {{ word("You need to enter a complete e-mail address.") | tojson }}
            }
        },
        'errorClass': 'da-has-error invalid-feedback'
    });
    $("a[data-embaction]").click(daEmbeddedAction);
    $("a[data-js]").click(daEmbeddedJs);
    $("a.da-review-action").click(daReviewAction);
    const embededInput = $("input.dainput-embedded");
    embededInput.on('keyup', daAdjustInputWidth);
    embededInput.each(daAdjustInputWidth);
    $('label a[data-bs-toggle="popover"]').on('click', function (event) {
        event.preventDefault();
        event.stopPropagation();
        let thePopover = bootstrap.Popover.getOrCreateInstance(this);
        thePopover.show();
        return false;
    });
    if (daPhoneAvailable) {
        $("#daPhoneAvailable").removeClass("dainvisible");
    }
    $(".daquestionbackbutton").on('click', function (event) {
        event.preventDefault();
        $("#dabackbutton").submit();
        return false;
    });
    $("#dabackbutton").on('submit', function (event) {
        if (daShowingHelp) {
            event.preventDefault();
            $('#daquestionlabel').tab('show');
            return false;
        }
        $("#dabackbutton").addClass("dabackiconpressed");
        let informed = '';
        if (daInformedChanged) {
            informed = '&informed=' + Object.keys(daInformed).join(',');
        }
        let url;
        if (daJsEmbed) {
            url = daPostURL;
        } else {
            url = $("#dabackbutton").attr('action');
        }
        $.ajax({
            type: "POST",
            url: url,
            beforeSend: addCsrfHeader,
            xhrFields: {
                withCredentials: true
            },
            data: $("#dabackbutton").serialize() + '&ajax=1' + informed,
            success: function (data) {
                setTimeout(function () {
                    daProcessAjax(data, document.getElementById('backbutton'), 1);
                }, 0);
            },
            error: function (xhr, status, error) {
                setTimeout(function () {
                    daProcessAjaxError(xhr, status, error);
                }, 0);
            }
        });
        daSpinnerTimeout = setTimeout(daShowSpinner, 1000);
        event.preventDefault();
    });
    $("#daChatOnButton").click(daRingChat);
    $("#daChatOffButton").click(daCloseChat);
    $('#daMessage').bind('keypress keydown keyup', function (e) {
        let theCode = e.which || e.keyCode;
        if (theCode == 13) {
            daSender();
            e.preventDefault();
        }
    });
    $('#daform button[type="submit"]').click(function () {
        daSubmitter = this;
        document.activeElement.blur();
        return true;
    });
    $('#daform input[type="submit"]').click(function () {
        daSubmitter = this;
        document.activeElement.blur();
        return true;
    });
    $('#daemailform button[type="submit"]').click(function () {
        daSubmitter = this;
        return true;
    });
    $('#dadownloadform button[type="submit"]').click(function () {
        daSubmitter = this;
        return true;
    });
    $(".danavlinks a.daclickable").click(function (e) {
        let the_key = $(this).data('key');
        da_action_perform("_da_priority_action", {_action: the_key});
        e.preventDefault();
        return false;
    });
    $(".danav-vertical .danavnested").each(function () {
        let box = this;
        let prev = $(this).prev();
        if (prev && !prev.hasClass('active')) {
            let toggler;
            if ($(box).hasClass('danotshowing')) {
                toggler = $('<a href="#" class="toggler" role="button" aria-pressed="false">');
                $('<i class="fas fa-caret-right">').appendTo(toggler);
            } else {
                toggler = $('<a href="#" class="toggler" role="button" aria-pressed="true">');
                $('<i class="fas fa-caret-down">').appendTo(toggler);
            }
            toggler.appendTo(prev);
            toggler.on('click', function (e) {
                let oThis = this;
                $(this).find("svg").each(function () {
                    if ($(this).attr('data-icon') == 'caret-down') {
                        $(this).removeClass('fa-caret-down');
                        $(this).addClass('fa-caret-right');
                        $(this).attr('data-icon', 'caret-right');
                        $(box).hide();
                        $(oThis).attr('aria-pressed', 'false');
                        $(box).toggleClass('danotshowing');
                    } else if ($(this).attr('data-icon') == 'caret-right') {
                        $(this).removeClass('fa-caret-right');
                        $(this).addClass('fa-caret-down');
                        $(this).attr('data-icon', 'caret-down');
                        $(box).show();
                        $(oThis).attr('aria-pressed', 'true');
                        $(box).toggleClass('danotshowing');
                    }
                });
                e.stopPropagation();
                e.preventDefault();
                return false;
            });
        }
    });
    $("body").focus();
    if (!daJsEmbed) {
        setTimeout(function () {
            let firstInput = $("#daform .da-field-container").not(".da-field-container-note").first().find("input, textarea, select").filter(":visible").first();
            if (firstInput.length > 0 && $(firstInput).visible()) {
                $(firstInput).focus();
                let inputType = $(firstInput).attr('type');
                if ($(firstInput).prop('tagName') != 'SELECT' && inputType !== "checkbox" && inputType !== "radio" && inputType !== "hidden" && inputType !== "submit" && inputType !== "file" && inputType !== "range" && inputType !== "number" && inputType !== "date" && inputType !== "time") {
                    let strLength = $(firstInput).val().length * 2;
                    if (strLength > 0) {
                        try {
                            $(firstInput)[0].setSelectionRange(strLength, strLength);
                        } catch (err) {
                            console.log(err.message);
                        }
                    }
                }
            } else {
                let firstButton = $("#danavbar-collapse .nav-link").filter(':visible').first();
                if (firstButton.length > 0 && $(firstButton).visible()) {
                    setTimeout(function () {
                        $(firstButton).focus();
                        $(firstButton).blur();
                    }, 0);
                }
            }
        }, 15);
    }
    $(".dauncheckspecificothers").on('change', function () {
        if ($(this).is(":checked")) {
            let theIds = $.parseJSON(atob($(this).data('unchecklist')));
            let n = theIds.length;
            for (let i = 0; i < n; ++i) {
                let elem = document.getElementById(theIds[i]);
                $(elem).prop("checked", false);
                $(elem).trigger('change');
            }
        }
    });
    $(".dauncheckspecificothers").each(function () {
        let theIds = $.parseJSON(atob($(this).data('unchecklist')));
        let n = theIds.length;
        let oThis = this;
        for (let i = 0; i < n; ++i) {
            let elem = document.getElementById(theIds[i]);
            $(elem).on('change', function () {
                if ($(this).is(":checked")) {
                    $(oThis).prop("checked", false);
                    $(oThis).trigger('change');
                }
            });
        }
    });
    $(".dauncheckothers").on('change', function () {
        if ($(this).is(":checked")) {
            $(".dauncheckable").prop("checked", false);
            $(".dauncheckable").trigger('change');
        }
    });
    $(".dauncheckable").on('change', function () {
        if ($(this).is(":checked")) {
            $(".dauncheckothers").prop("checked", false);
            $(".dauncheckothers").trigger('change');
        }
    });
    let navMain = $("#danavbar-collapse");
    navMain.on("click", "a", null, function () {
        if (!($(this).hasClass("dropdown-toggle"))) {
            navMain.collapse('hide');
        }
    });
    $("button[data-bs-target='#dahelp']").on("shown.bs.tab", function () {
        if (daJsEmbed) {
            $(daTargetDiv)[0].scrollTo(0, 1);
        } else {
            window.scrollTo(0, 1);
        }
        $("#dahelptoggle").removeClass('daactivetext');
        $("#dahelptoggle").blur();
    });
    $("#dasourcetoggle").on("click", function () {
        $(this).parent().toggleClass("active");
        $(this).blur();
    });
    $('#dabackToQuestion').click(function (event) {
        $('#daquestionlabel').tab('show');
    });
    daVarLookup = Object();
    daVarLookupRev = Object();
    daVarLookupMulti = Object();
    daVarLookupRevMulti = Object();
    if ($("input[name='_varnames']").length) {
        the_hash = $.parseJSON(atob($("input[name='_varnames']").val()));
        for (let key in the_hash) {
            if (the_hash.hasOwnProperty(key)) {
                daVarLookup[the_hash[key]] = key;
                daVarLookupRev[key] = the_hash[key];
                if (!daVarLookupMulti.hasOwnProperty(the_hash[key])) {
                    daVarLookupMulti[the_hash[key]] = [];
                }
                daVarLookupMulti[the_hash[key]].push(key);
                if (!daVarLookupRevMulti.hasOwnProperty(key)) {
                    daVarLookupRevMulti[key] = [];
                }
                daVarLookupRevMulti[key].push(the_hash[key]);
            }
        }
    }
    if ($("input[name='_checkboxes']").length) {
        let patt = new RegExp(/\[B['"][^\]]*['"]]$/);
        let pattRaw = new RegExp(/\[R['"][^\]]*['"]]$/);
        the_hash = $.parseJSON(atob($("input[name='_checkboxes']").val()));
        for (let key in the_hash) {
            if (the_hash.hasOwnProperty(key)) {
                let checkboxName = atob(key);
                let baseName = checkboxName;
                if (patt.test(baseName)) {
                    bracketPart = checkboxName.replace(/^.*(\[B?['"][^\]]*['"]\])$/, "$1");
                    checkboxName = checkboxName.replace(/^.*\[B?['"]([^\]]*)['"]\]$/, "$1");
                    baseName = baseName.replace(/^(.*)\[.*/, "$1");
                    let transBaseName = baseName;
                    if (($("[name='" + key + "']").length === 0) && (typeof daVarLookup[btoa(transBaseName).replace(/[\n=]/g, '')] != "undefined")) {
                        transBaseName = atob(daVarLookup[btoa(transBaseName).replace(/[\n=]/g, '')]);
                    }
                    let convertedName;
                    try {
                        convertedName = atob(checkboxName);
                    } catch (e) {
                        continue;
                    }
                    let daNameOne = btoa(transBaseName + bracketPart).replace(/[\n=]/g, '');
                    let daNameTwo = btoa(baseName + "['" + convertedName + "']").replace(/[\n=]/g, '');
                    let daNameThree = btoa(baseName + '["' + convertedName + '"]').replace(/[\n=]/g, '');
                    daVarLookupRev[daNameOne] = daNameTwo;
                    daVarLookup[daNameTwo] = daNameOne;
                    daVarLookup[daNameThree] = daNameOne;
                    if (!daVarLookupRevMulti.hasOwnProperty(daNameOne)) {
                        daVarLookupRevMulti[daNameOne] = [];
                    }
                    daVarLookupRevMulti[daNameOne].push(daNameTwo);
                    if (!daVarLookupMulti.hasOwnProperty(daNameTwo)) {
                        daVarLookupMulti[daNameTwo] = [];
                    }
                    daVarLookupMulti[daNameTwo].push(daNameOne);
                    if (!daVarLookupMulti.hasOwnProperty(daNameThree)) {
                        daVarLookupMulti[daNameThree] = [];
                    }
                    daVarLookupMulti[daNameThree].push(daNameOne);
                } else if (pattRaw.test(baseName)) {
                    bracketPart = checkboxName.replace(/^.*(\[R?['"][^\]]*['"]\])$/, "$1");
                    checkboxName = checkboxName.replace(/^.*\[R?['"]([^\]]*)['"]\]$/, "$1");
                    baseName = baseName.replace(/^(.*)\[.*/, "$1");
                    let transBaseName = baseName;
                    if (($("[name='" + key + "']").length === 0) && (typeof daVarLookup[btoa(transBaseName).replace(/[\n=]/g, '')] != "undefined")) {
                        transBaseName = atob(daVarLookup[btoa(transBaseName).replace(/[\n=]/g, '')]);
                    }
                    let convertedName;
                    try {
                        convertedName = atob(checkboxName);
                    } catch (e) {
                        continue;
                    }
                    let daNameOne = btoa(transBaseName + bracketPart).replace(/[\n=]/g, '');
                    let daNameTwo = btoa(baseName + "[" + convertedName + "]").replace(/[\n=]/g, '')
                    daVarLookupRev[daNameOne] = daNameTwo;
                    daVarLookup[daNameTwo] = daNameOne;
                    if (!daVarLookupRevMulti.hasOwnProperty(daNameOne)) {
                        daVarLookupRevMulti[daNameOne] = [];
                    }
                    daVarLookupRevMulti[daNameOne].push(daNameTwo);
                    if (!daVarLookupMulti.hasOwnProperty(daNameTwo)) {
                        daVarLookupMulti[daNameTwo] = [];
                    }
                    daVarLookupMulti[daNameTwo].push(daNameOne);
                }
            }
        }
    }
    daShowIfInProcess = true;
    let daTriggerQueries = [];

    function daOnlyUnique(value, index, self) {
        return self.indexOf(value) === index;
    }

    $(".dajsshowif").each(function () {
        let showIfDiv = this;
        let jsInfo = JSON.parse(atob($(this).data('jsshowif')));
        let showIfSign = jsInfo['sign'];
        let showIfMode = jsInfo['mode'];
        let jsExpression = jsInfo['expression'];
        let n = jsInfo['vars'].length;
        for (let i = 0; i < n; ++i) {
            let showIfVars = [];
            let initShowIfVar = btoa(jsInfo['vars'][i]).replace(/[\n=]/g, '');
            let initShowIfVarEscaped = initShowIfVar.replace(/(:|\.|\[|\]|,|=)/g, "\\$1");
            let elem = $("[name='" + initShowIfVarEscaped + "']");
            if (elem.length > 0) {
                showIfVars.push(initShowIfVar);
            }
            if (daVarLookupMulti.hasOwnProperty(initShowIfVar)) {
                for (let j = 0; j < daVarLookupMulti[initShowIfVar].length; j++) {
                    let altShowIfVar = daVarLookupMulti[initShowIfVar][j];
                    let altShowIfVarEscaped = altShowIfVar.replace(/(:|\.|\[|\]|,|=)/g, "\\$1");
                    let altElem = $("[name='" + altShowIfVarEscaped + "']");
                    if (altElem.length > 0 && !$.contains(this, altElem[0])) {
                        showIfVars.push(altShowIfVar);
                    }
                }
            }
            if (showIfVars.length === 0) {
                console.log("ERROR: reference to non-existent field " + jsInfo['vars'][i]);
            }
            for (let j = 0; j < showIfVars.length; ++j) {
                let showIfVar = showIfVars[j];
                let showIfVarEscaped = showIfVar.replace(/(:|\.|\[|\]|,|=)/g, "\\$1");
                let showHideDiv = function (speed) {
                    let elem = daGetField(jsInfo['vars'][i]);
                    if (elem != null && !$(elem).parents('.da-form-group').first().is($(this).parents('.da-form-group').first())) {
                        return;
                    }
                    let resultt = eval(jsExpression);
                    if (resultt) {
                        if (showIfSign) {
                            if ($(showIfDiv).data('isVisible') != '1') {
                                daShowHideHappened = true;
                            }
                            if (showIfMode == 0) {
                                $(showIfDiv).show(speed);
                            }
                            $(showIfDiv).data('isVisible', '1');
                            $(showIfDiv).find('input, textarea, select').prop("disabled", false);
                            $(showIfDiv).find('input.combobox').each(function () {
                                daComboBoxes[$(this).attr('id')].enable();
                            });
                        } else {
                            if ($(showIfDiv).data('isVisible') != '0') {
                                daShowHideHappened = true;
                            }
                            if (showIfMode == 0) {
                                $(showIfDiv).hide(speed);
                            }
                            $(showIfDiv).data('isVisible', '0');
                            $(showIfDiv).find('input, textarea, select').prop("disabled", true);
                            $(showIfDiv).find('input.combobox').each(function () {
                                daComboBoxes[$(this).attr('id')].disable();
                            });
                        }
                    } else {
                        if (showIfSign) {
                            if ($(showIfDiv).data('isVisible') != '0') {
                                daShowHideHappened = true;
                            }
                            if (showIfMode == 0) {
                                $(showIfDiv).hide(speed);
                            }
                            $(showIfDiv).data('isVisible', '0');
                            $(showIfDiv).find('input, textarea, select').prop("disabled", true);
                            $(showIfDiv).find('input.combobox').each(function () {
                                daComboBoxes[$(this).attr('id')].disable();
                            });
                        } else {
                            if ($(showIfDiv).data('isVisible') != '1') {
                                daShowHideHappened = true;
                            }
                            if (showIfMode == 0) {
                                $(showIfDiv).show(speed);
                            }
                            $(showIfDiv).data('isVisible', '1');
                            $(showIfDiv).find('input, textarea, select').prop("disabled", false);
                            $(showIfDiv).find('input.combobox').each(function () {
                                daComboBoxes[$(this).attr('id')].enable();
                            });
                        }
                    }
                    let daThis = this;
                    if (!daShowIfInProcess) {
                        daShowIfInProcess = true;
                        $(":input").not("[type='file']").each(function () {
                            if (this != daThis) {
                                $(this).trigger('change');
                            }
                        });
                        daShowIfInProcess = false;
                    }
                };
                let showHideDivImmediate = function () {
                    showHideDiv.apply(this, [null]);
                }
                let showHideDivFast = function () {
                    showHideDiv.apply(this, ['fast']);
                }
                daTriggerQueries.push("#" + showIfVarEscaped);
                daTriggerQueries.push("input[type='radio'][name='" + showIfVarEscaped + "']");
                daTriggerQueries.push("input[type='checkbox'][name='" + showIfVarEscaped + "']");
                $("#" + showIfVarEscaped).change(showHideDivFast);
                $("input[type='radio'][name='" + showIfVarEscaped + "']").change(showHideDivFast);
                $("input[type='checkbox'][name='" + showIfVarEscaped + "']").change(showHideDivFast);
                $("#" + showIfVarEscaped).on('daManualTrigger', showHideDivImmediate);
                $("input[type='radio'][name='" + showIfVarEscaped + "']").on('daManualTrigger', showHideDivImmediate);
                $("input[type='checkbox'][name='" + showIfVarEscaped + "']").on('daManualTrigger', showHideDivImmediate);
            }
        }
    });
    $(".dashowif").each(function () {
        let showIfVars = [];
        let showIfSign = $(this).data('showif-sign');
        let showIfMode = parseInt($(this).data('showif-mode'));
        let initShowIfVar = $(this).data('showif-let');
        let varName = atob(initShowIfVar);
        let initShowIfVarEscaped = initShowIfVar.replace(/(:|\.|\[|\]|,|=)/g, "\\$1");
        let elem = $("[name='" + initShowIfVarEscaped + "']");
        if (elem.length > 0) {
            showIfVars.push(initShowIfVar);
        }
        if (daVarLookupMulti.hasOwnProperty(initShowIfVar)) {
            let n = daVarLookupMulti[initShowIfVar].length;
            for (let i = 0; i < n; i++) {
                let altShowIfVar = daVarLookupMulti[initShowIfVar][i];
                let altShowIfVarEscaped = altShowIfVar.replace(/(:|\.|\[|\]|,|=)/g, "\\$1");
                let altElem = $("[name='" + altShowIfVarEscaped + "']");
                if (altElem.length > 0 && !$.contains(this, altElem[0])) {
                    showIfVars.push(altShowIfVar);
                }
            }
        }
        let showIfVal = $(this).data('showif-val');
        let saveAs = $(this).data('saveas');
        let showIfDiv = this;
        let n = showIfVars.length;
        for (let i = 0; i < n; ++i) {
            let showIfVar = showIfVars[i];
            let showIfVarEscaped = showIfVar.replace(/(:|\.|\[|\]|,|=)/g, "\\$1");
            let showHideDiv = function (speed) {
                let elem = daGetField(varName, showIfDiv);
                if (elem != null && !$(elem).parents('.da-form-group').first().is($(this).parents('.da-form-group').first())) {
                    return;
                }
                let theVal;
                let showifParents = $(this).parents(".dashowif");
                if (showifParents.length !== 0 && !($(showifParents[0]).data("isVisible") == '1')) {
                    theVal = '';
                    //console.log("Setting theVal to blank.");
                } else if ($(this).attr('type') === "checkbox") {
                    theVal = $("input[name='" + showIfVarEscaped + "']:checked").val();
                    if (typeof (theVal) == 'undefined') {
                        //console.log('manually setting checkbox value to False');
                        theVal = 'False';
                    }
                } else if ($(this).attr('type') === "radio") {
                    theVal = $("input[name='" + showIfVarEscaped + "']:checked").val();
                    if (typeof (theVal) == 'undefined') {
                        theVal = '';
                    } else if (theVal != '' && $("input[name='" + showIfVarEscaped + "']:checked").hasClass("daobject")) {
                        try {
                            theVal = atob(theVal);
                        } catch (e) {
                        }
                    }
                } else {
                    theVal = $(this).val();
                    if (theVal != '' && $(this).hasClass("daobject")) {
                        try {
                            theVal = atob(theVal);
                        } catch (e) {
                        }
                    }
                }
                //console.log("this is " + $(this).attr('id') + " and saveAs is " + atob(saveAs) + " and showIfVar is " + atob(showIfVar) + " and val is " + String(theVal) + " and showIfVal is " + String(showIfVal));
                if (daShowIfCompare(theVal, showIfVal)) {
                    if (showIfSign) {
                        if ($(showIfDiv).data('isVisible') != '1') {
                            daShowHideHappened = true;
                        }
                        if (showIfMode == 0) {
                            $(showIfDiv).show(speed);
                        }
                        $(showIfDiv).data('isVisible', '1');
                        let firstChild = $(showIfDiv).children()[0];
                        if (!$(firstChild).hasClass('dacollectextra') || $(firstChild).is(":visible")) {
                            $(showIfDiv).find('input, textarea, select').prop("disabled", false);
                            $(showIfDiv).find('input.combobox').each(function () {
                                daComboBoxes[$(this).attr('id')].enable();
                            });
                        }
                    } else {
                        if ($(showIfDiv).data('isVisible') != '0') {
                            daShowHideHappened = true;
                        }
                        if (showIfMode == 0) {
                            $(showIfDiv).hide(speed);
                        }
                        $(showIfDiv).data('isVisible', '0');
                        $(showIfDiv).find('input, textarea, select').prop("disabled", true);
                        $(showIfDiv).find('input.combobox').each(function () {
                            daComboBoxes[$(this).attr('id')].disable();
                        });
                    }
                } else {
                    if (showIfSign) {
                        if ($(showIfDiv).data('isVisible') != '0') {
                            daShowHideHappened = true;
                        }
                        if (showIfMode == 0) {
                            $(showIfDiv).hide(speed);
                        }
                        $(showIfDiv).data('isVisible', '0');
                        $(showIfDiv).find('input, textarea, select').prop("disabled", true);
                        $(showIfDiv).find('input.combobox').each(function () {
                            daComboBoxes[$(this).attr('id')].disable();
                        });
                    } else {
                        if ($(showIfDiv).data('isVisible') != '1') {
                            daShowHideHappened = true;
                        }
                        if (showIfMode == 0) {
                            $(showIfDiv).show(speed);
                        }
                        $(showIfDiv).data('isVisible', '1');
                        let firstChild = $(showIfDiv).children()[0];
                        if (!$(firstChild).hasClass('dacollectextra') || $(firstChild).is(":visible")) {
                            $(showIfDiv).find('input, textarea, select').prop("disabled", false);
                            $(showIfDiv).find('input.combobox').each(function () {
                                daComboBoxes[$(this).attr('id')].enable();
                            });
                        }
                    }
                }
                let daThis = this;
                if (!daShowIfInProcess) {
                    daShowIfInProcess = true;
                    $(":input").not("[type='file']").each(function () {
                        if (this != daThis) {
                            $(this).trigger('change');
                        }
                    });
                    daShowIfInProcess = false;
                }
            };
            let showHideDivImmediate = function () {
                showHideDiv.apply(this, [null]);
            }
            let showHideDivFast = function () {
                showHideDiv.apply(this, ['fast']);
            }
            daTriggerQueries.push("#" + showIfVarEscaped);
            daTriggerQueries.push("input[type='radio'][name='" + showIfVarEscaped + "']");
            daTriggerQueries.push("input[type='checkbox'][name='" + showIfVarEscaped + "']");
            $("#" + showIfVarEscaped).change(showHideDivFast);
            $("#" + showIfVarEscaped).on('daManualTrigger', showHideDivImmediate);
            $("input[type='radio'][name='" + showIfVarEscaped + "']").change(showHideDivFast);
            $("input[type='radio'][name='" + showIfVarEscaped + "']").on('daManualTrigger', showHideDivImmediate);
            $("input[type='checkbox'][name='" + showIfVarEscaped + "']").change(showHideDivFast);
            $("input[type='checkbox'][name='" + showIfVarEscaped + "']").on('daManualTrigger', showHideDivImmediate);
        }
    });

    function daTriggerAllShowHides() {
        let daUniqueTriggerQueries = daTriggerQueries.filter(daOnlyUnique);
        let daFirstTime = true;
        let daTries = 0;
        while ((daFirstTime || daShowHideHappened) && ++daTries < 100) {
            daShowHideHappened = false;
            daFirstTime = false;
            let n = daUniqueTriggerQueries.length;
            for (let i = 0; i < n; ++i) {
                $(daUniqueTriggerQueries[i]).trigger('daManualTrigger');
            }
        }
        if (daTries >= 100) {
            console.log("Too many contradictory 'show if' conditions");
        }
    }

    if (daTriggerQueries.length > 0) {
        daTriggerAllShowHides();
    }
    $(".danavlink").last().addClass('thelast');
    $(".danavlink").each(function () {
        if ($(this).hasClass('btn') && !$(this).hasClass('danotavailableyet')) {
            let the_a = $(this);
            let the_delay = 1000 + 250 * parseInt($(this).data('index'));
            setTimeout(function () {
                $(the_a).removeClass('{{ button_style }}secondary');
                if ($(the_a).hasClass('active')) {
                    $(the_a).addClass('{{ button_style }}success');
                } else {
                    $(the_a).addClass('{{ button_style }}warning');
                }
            }, the_delay);
        }
    });
    daShowIfInProcess = false;
    $("#daSend").click(daSender);
    if (daChatAvailable == 'unavailable') {
        daChatStatus = 'off';
    }
    if (daChatAvailable == 'observeonly') {
        daChatStatus = 'observeonly';
    }
    if ((daChatStatus === 'off' || daChatStatus === 'observeonly') && daChatAvailable == 'available') {
        daChatStatus = 'waiting';
    }
    daDisplayChat();
    if (daBeingControlled) {
        daShowControl('fast');
    }
    if (daChatStatus === 'ready' || daBeingControlled) {
        daInitializeSocket();
    }
    if (daInitialized == false && daCheckinSeconds > 0) { // why was this set to always retrieve the chat log?
        setTimeout(function () {
            //console.log("daInitialize call to chat_log in checkin");
            $.ajax({
                type: 'POST',
                url: '{{ url_for("checkin", i=yaml_filename) }}',
                beforeSend: addCsrfHeader,
                xhrFields: {
                    withCredentials: true
                },
                data: $.param({action: 'chat_log', ajax: '1', csrf_token: daCsrf}),
                success: daChatLogCallback,
                dataType: 'json'
            });
        }, 200);
    }
    if (daInitialized == true) {
        //console.log("Publishing from memory");
        $("#daCorrespondence").html('');
        for (let i = 0; i < daChatHistory.length; i++) {
            daPublishMessage(daChatHistory[i]);
        }
    }
    if (daChatStatus !== 'off') {
        daSendChanges = true;
    } else {
        if (daDoAction == null) {
            daSendChanges = false;
        } else {
            daSendChanges = true;
        }
    }
    if (daSendChanges) {
        $("#daform").each(function () {
            $(this).find(':input').change(daPushChanges);
        });
    }
    daInitialized = true;
    daShowingHelp = 0;
    daSubmitter = null;
    setTimeout(function () {
        $("#daflash .alert-success").hide(300, function () {
            $(self).remove();
        });
    }, 3000);
    if (doScroll) {
        setTimeout(function () {
            if (daJsEmbed) {
                $(daTargetDiv)[0].scrollTo(0, 1);
                if (daSteps > 1) {
                    $(daTargetDiv)[0].scrollIntoView();
                }
            } else {
                window.scrollTo(0, 1);
            }
        }, 20);
    }
    if (daShowingSpinner) {
        daHideSpinner();
    }
    if (daCheckinInterval != null) {
        clearInterval(daCheckinInterval);
    }
    if (daCheckinSeconds > 0) {
        setTimeout(daCheckin, 100);
        daCheckinInterval = setInterval(daCheckin, daCheckinSeconds);
    }
    daShowNotifications();
    if (daUsingGA) {
        daPageview();
    }
    if (daUsingSegment) {
        daSegmentEvent();
    }
    hideTablist();
    $(document).trigger('daPageLoad');
}
$(document).ready(function () {
    daInitialize(1);
    //console.log("ready: replaceState " + daSteps);
    if (!daJsEmbed && !daIframeEmbed) {
        history.replaceState({steps: daSteps}, "", daLocationBar + {{ page_sep | tojson }} +daSteps);
    }
    let daReloadAfter = {{ reload_after }};
    if (daReloadAfter > 0) {
        daReloader = setTimeout(function () {
            daRefreshSubmit();
        }, daReloadAfter);
    }
    window.onpopstate = function (event) {
        if (event.state != null && event.state.steps < daSteps && daAllowGoingBack) {
            $("#dabackbutton").submit();
        }
    };
    $(window).bind('unload', function () {
        daStopCheckingIn();
        if (daSocket != null && daSocket.connected) {
            //console.log('Terminating interview socket because window unloaded');
            daSocket.emit('terminate');
        }
    });
    let daDefaultAllowList = bootstrap.Tooltip.Default.allowList;
    daDefaultAllowList['*'].push('style');
    daDefaultAllowList['a'].push('style');
    daDefaultAllowList['img'].push('style');
    if (daJsEmbed) {
        $.ajax({
            type: "POST",
            url: daPostURL,
            beforeSend: addCsrfHeader,
            xhrFields: {
                withCredentials: true
            },
            data: 'csrf_token=' + daCsrf + '&ajax=1',
            success: function (data) {
                setTimeout(function () {
                    daProcessAjax(data, $("#daform"), 0);
                }, 0);
            },
            error: function (xhr, status, error) {
                setTimeout(function () {
                    daProcessAjaxError(xhr, status, error);
                }, 0);
            }
        });
    }
});
$(window).ready(daUpdateHeight);
$(window).resize(daUpdateHeight);
function daUpdateHeight() {
    $(".dagoogleMap").each(function () {
        let size = $(this).width();
        $(this).css('height', size);
    });
}
$.validator.setDefaults({
    highlight: function (element) {
        $(element).closest('.da-form-group').addClass('da-group-has-error');
        $(element).addClass('is-invalid');
    },
    unhighlight: function (element) {
        $(element).closest('.da-form-group').removeClass('da-group-has-error');
        $(element).removeClass('is-invalid');
    },
    errorElement: 'span',
    errorClass: 'da-has-error invalid-feedback',
    errorPlacement: function (error, element) {
        $(error).addClass('invalid-feedback');
        let elementName = $(element).attr("name");
        let lastInGroup = $.map(daValidationRules['groups'], function (thefields, thename) {
            let fieldsArr;
            if (thefields.indexOf(elementName) >= 0) {
                fieldsArr = thefields.split(" ");
                return fieldsArr[fieldsArr.length - 1];
            } else {
                return null;
            }
        })[0];
        if (element.hasClass('dainput-embedded')) {
            error.insertAfter(element);
        } else if (element.hasClass('dafile-embedded')) {
            error.insertAfter(element);
        } else if (element.hasClass('daradio-embedded')) {
            element.parent().append(error);
        } else if (element.hasClass('dacheckbox-embedded')) {
            element.parent().append(error);
        } else if (element.hasClass('dauncheckable') && lastInGroup) {
            $("input[name='" + lastInGroup + "']").parent().append(error);
        } else if (element.parent().hasClass('combobox-container')) {
            error.insertAfter(element.parent());
        } else if (element.hasClass('dafile')) {
            let fileContainer = $(element).parents(".file-input").first();
            if (fileContainer.length > 0) {
                $(fileContainer).append(error);
            } else {
                error.insertAfter(element.parent());
            }
        } else if (element.parent('.input-group').length) {
            error.insertAfter(element.parent());
        } else if (element.hasClass('da-active-invisible')) {
            let choice_with_help = $(element).parents(".dachoicewithhelp").first();
            if (choice_with_help.length > 0) {
                $(choice_with_help).parent().append(error);
            } else {
                element.parent().append(error);
            }
        } else if (element.hasClass('danon-nota-checkbox')) {
            element.parent().append(error);
        } else {
            error.insertAfter(element);
        }
    }
});
$.validator.addMethod("datetime", function (a, b) {
    return true;
});
$.validator.addMethod("ajaxrequired", function (value, element, params) {
    let realElement = $("#" + $(element).attr('name') + "combobox");
    let realValue = $(realElement).val();
    if (!$(realElement).parent().is(":visible")) {
        return true;
    }
    if (realValue == null || realValue.replace(/\s/g, '') === '') {
        return false;
    }
    return true;
});
$.validator.addMethod('checkone', function (value, element, params) {
    let number_needed = params[0];
    let css_query = params[1];
    if ($(css_query).length >= number_needed) {
        return true;
    } else {
        return false;
    }
});
$.validator.addMethod('checkatleast', function (value, element, params) {
    if ($(element).attr('name') !== '_ignore' + params[0]) {
        return true;
    }
    if ($('.dafield' + params[0] + ':checked').length >= params[1]) {
        return true;
    } else {
        return false;
    }
});
$.validator.addMethod('checkatmost', function (value, element, params) {
    if ($(element).attr('name') !== '_ignore' + params[0]) {
        return true;
    }
    if ($('.dafield' + params[0] + ':checked').length > params[1]) {
        return false;
    } else {
        return true;
    }
});
$.validator.addMethod('checkexactly', function (value, element, params) {
    if ($(element).attr('name') !== '_ignore' + params[0]) {
        return true;
    }
    if ($('.dafield' + params[0] + ':checked').length !== params[1]) {
        return false;
    } else {
        return true;
    }
});
$.validator.addMethod('selectexactly', function (value, element, params) {
    if ($(element).find('option:selected').length === params[0]) {
        return true;
    } else {
        return false;
    }
});
$.validator.addMethod('mindate', function (value, element, params) {
    if (value == null || value == '') {
        return true;
    }
    try {
        let date = new Date(value);
        let comparator = new Date(params);
        if (date >= comparator) {
            return true;
        }
    } catch (e) {
    }
    return false;
});
$.validator.addMethod('maxdate', function (value, element, params) {
    if (value == null || value == '') {
        return true;
    }
    try {
        let date = new Date(value);
        let comparator = new Date(params);
        if (date <= comparator) {
            return true;
        }
    } catch (e) {
    }
    return false;
});
$.validator.addMethod('minmaxdate', function (value, element, params) {
    if (value == null || value == '') {
        return true;
    }
    try {
        let date = new Date(value);
        let before_comparator = new Date(params[0]);
        let after_comparator = new Date(params[1]);
        if (date >= before_comparator && date <= after_comparator) {
            return true;
        }
    } catch (e) {
    }
    return false;
});
$.validator.addMethod('maxuploadsize', function (value, element, param) {
    try {
        let limit = parseInt(param) - 2000;
        if (limit <= 0) {
            return true;
        }
        let maxImageSize;
        if ($(element).data('maximagesize')) {
            maxImageSize = (parseInt($(element).data('maximagesize')) * parseInt($(element).data('maximagesize'))) * 2;
        } else {
            maxImageSize = 0;
        }
        if ($(element).attr("type") === "file") {
            if (element.files && element.files.length) {
                let totalSize = 0;
                for (i = 0; i < element.files.length; i++) {
                    if (maxImageSize > 0 && element.files[i].size > (0.20 * maxImageSize) && element.files[i].type.match(/image.*/) && !(element.files[i].type.indexOf('image/svg') === 0)) {
                        totalSize += maxImageSize;
                    } else {
                        totalSize += element.files[i].size;
                    }
                }
                if (totalSize > limit) {
                    return false;
                }
            }
            return true;
        }
    } catch (e) {
    }
    return false;
});

{% for custom_type in custom_data_types %}
{% set info = custom_types[custom_type] %}
{% if isinstance(info['javascript'], str) %}
try {
    {{ info['javascript'].strip().rstrip()  }}
} catch (e) {
    console.error('Error with JavaScript code of CustomDataType {{ info['class'].__name__ }}', e);
}
{% endif %}
{% endfor %}

{% if question_data is not none %}
daQuestionData = {{ question_data | tojson }}
{% endif %}