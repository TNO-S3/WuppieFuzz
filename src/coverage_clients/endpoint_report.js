// When the document is loaded, attach "onclick" events to all links of class
// 'input-link' that display the 'data-input' contents in the 'input-pane'
// and 'data-output' in the 'output-pane'.
function update_hidden() {
    $("ul.path").children().each(function(index, element) {
        $(element).show();
    });
    $("ul.method").children().each(function(index, element) {
        $(element).show();
    });

    if ($("#f-hit")[0].checked) {
        $(".c-hit").parent().show();
    } else {
        $(".c-hit").parent().hide();
    }
    if ($("#f-miss")[0].checked) {
        $(".c-miss").parent().show();
    } else {
        $(".c-miss").parent().hide();
    }
    if ($("#f-extra")[0].checked) {
        $(".c-extra").parent().show();
    } else {
        $(".c-extra").parent().hide();
    }

    $("ul.method").children().each(function(index, element) {
        if ($(element).children().children().children().filter(function(index, child) {
            // is(":visible") (rather than checking the child's own "display" style)
            // correctly treats the hidden fault-variants <li> (which has no inline
            // display:none of its own, only a hidden child div, see
            // `export_filesystem`) as invisible too, since it renders with zero size.
            return $(child).is(":visible");
        }).length > 0) { // has visible children?
            $(element).show();
        } else {
            $(element).hide();
        }
    });
    $("ul.path").children().each(function(index, element) {
        if ($(element).children().children().children().filter(function(index, child) {
            return $(child).is(":visible");
        }).length > 0) { // has visible children?
            $(element).show();
        } else {
            $(element).hide();
        }
    });
}
$(function() {
    // Delegated handler so dynamically added markup (e.g. fault variants, which
    // are static blocks not links) doesn't need its own listener; only the base
    // tree items carry the "input-link" class that this targets.
    $(document).on("click", ".input-link", function() {
        $(".input-link").css("background-color", "#00000000");
        $(this).css("background-color", "#FFFF00FF"); 
        let maybe_validation_error = $(this).attr("validation-error");
        if (maybe_validation_error === undefined) {
            maybe_validation_error = "";
        } else {
            maybe_validation_error = " - " + maybe_validation_error;
        }
        let endpoint = $(this).closest('.endpoint_path')[0].firstChild.nodeValue;
        $("#title-header").html(endpoint);
        let http_method = $(this).closest('div')[0].firstChild.nodeValue;
        let http_result = $(this).html();
        let hit_miss_unspecified = http_result.substring(0, 2);
        let http_status = http_result.substring(2);
        $("#title-pane").html([hit_miss_unspecified, http_method, http_status].join(" ") + maybe_validation_error);
        // c-fault-only status codes (unspecified ones, or specified ones that were
        // only ever observed together with a validation fault - see `cover`) have a
        // request/response that is identical to one of their own fault variants, so
        // show a remark instead of duplicating that content in #input-pane/#output-pane.
        if ($(this).hasClass("c-fault-only")) {
            $("#request-response-section").hide();
            let remark = $(this).hasClass("c-extra")
                ? "This status code is not specified in the API; every occurrence of it was recorded as a fault. See the fault variant(s) below for details."
                : "This status code is specified in the API, but it was only ever observed together with a validation fault. See the fault variant(s) below for details.";
            $("#fault-only-remark").text(remark).show();
        } else {
            $("#input-pane").html($(this).attr("data-input"));
            $("#output-pane").html($(this).attr("data-output"));
            $("#request-response-section").show();
            $("#fault-only-remark").hide();
        }
        // Fault variants for this exact status, if any, live inside a hidden
        // <div class="fault-variants"> in the very next <li> sibling (see
        // `export_filesystem`); copy its contents (static request/response/
        // reproduce blocks, nothing left to wire up) into the visible pane.
        let variants = $(this).closest("li").next("li").children(".fault-variants");
        if (variants.length) {
            $("#fault-variants-pane").html(variants.html());
        } else {
            $("#fault-variants-pane").html("No faults recorded for this status.");
        }
    });
    $("input").click(update_hidden);
    $("label").click(update_hidden);
    $("input").prop("checked", true);

    $("#tab-endpoints").click(function () {
        $("#view-faults").hide();
        $("#view-endpoints").show();
        $("#filters").show();
        $(this).addClass("active");
        $("#tab-faults").removeClass("active");
    });
    $("#tab-faults").click(function () {
        $("#view-endpoints").hide();
        $("#view-faults").show();
        $("#filters").hide();
        $(this).addClass("active");
        $("#tab-endpoints").removeClass("active");
    });

    // Delegated handler: the faults table's copy buttons are generated dynamically,
    // so attach the listener to a static ancestor rather than the buttons themselves.
    $(document).on("click", ".copy-btn", function () {
        let text = $(this).attr("data-copy");
        navigator.clipboard.writeText(text).then(function () {
            let button = this;
            let original = $(button).text();
            $(button).text("Copied!");
            setTimeout(function () {
                $(button).text(original);
            }, 1500);
        }.bind(this));
    });
});

