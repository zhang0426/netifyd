<?php
require_once('guiconfig.inc');
require_once('/usr/local/pkg/netify/netify.inc');

if ($_POST['status'] == 'update') {
    $status = array('sink_enabled' => netifyd_sink_enabled());

    $response = json_encode($status);
    header('Content-Type: application/json');
    header('Content-Length: ' . strlen($response));

    echo json_encode($status);

    exit;
}
else if (array_key_exists('sinkEnable', $_POST)) {
    $enable = true;
    if ($_POST['sinkEnable'] == 'false') $enable = false;
    $status = array('result' => netifyd_enable_sink($enable));

    $response = json_encode($status);
    header('Content-Type: application/json');
    header('Content-Length: ' . strlen($response));

    echo json_encode($status);

    exit;
}

$pgtitle = array(gettext('Services'), gettext('Netify'), gettext('Provision'));

include('head.inc');

$tab_array = array();
$tab_array[] = array(gettext('Status'), false, '/netify/netify_status.php');
$tab_array[] = array(gettext('Provision'), true, '/netify/netify_provision.php');

display_top_tabs($tab_array, true);

$agent_uuid = netifyd_get_uuid();
$agent_status_url = netifyd_get_agent_status_url();

?>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title"><?=gettext("Provision Netify Agent")?></h2>
    </div>
    <div class="panel-body">
        <div class="content table-responsive">
            <div><img style="width: 18em; margin-bottom: 1em;" src="./images/netify.svg"></div>
            <table class="table table-striped table-condensed" style="margin-bottom: 1em;">
                <tr>
                    <th style='width: 40%; text-align: right; vertical-align: middle;'>Provision Code</th>
                    <td><span style="font-family: monospace; font-size: 1.3em;"><?=$agent_uuid;?></span><button id="btn-copy-code" class="fa fa-clipboard" style="font-size: 1.5em; margin-left: 0.5em;" title="<?=gettext("Copy Provision Code to clipboard.");?>"></button></td>
                </tr>
                <tr>
                    <th style='text-align: right; vertical-align: middle;'>Status</th>
                    <td><span id="provision-status" style="width: 25em; font-size: 1.5em;"><?=gettext("Loading...");?></span></td>
                </tr>
                <tr>
                    <th id="sink-status" style='text-align: right; vertical-align: middle;'><?=gettext("Sink Status");?></th>
                    <td>
                        <div id="sink-warning" class="text-danger" style="display: none; width: 25em;">
                            <p><?=gettext("Please enable the Netify Agent to report metadata back to the Netify Informatics Cloud Sink Server before attempting to provision.");?></p>
                        </div>
                        <div'><button id="btn-sink-enable" class="btn" style="width: 12em;" type="button" title="<?=gettext("Enable/disable access to the Netify Informatics Cloud Sink Server.");?>" disabled>...</button></div>
                    </td>
                </tr>
                <tr>
                    <td></td>
                    <td>
                        <button id="btn-provision" class="btn btn-success" style="width: 12em;" type="button" title="<?=gettext('Provision Agent on Netify Portal'); ?>">Provision Netify Agent</button>
                    </td>
                </tr>
            </table>
        </div>
    </div>
</div>

<script type="text/javascript">
//<![CDATA[
    var sinkEnabled = false;

    function init() {
        $(document).ready(function() {
            console.log('DOM ready.');
            $('#btn-provision').click(function() {
                console.log('Provision clicked.');
                window.open('http://netify.ai/get-netify');
                return false;
            });
            $('#btn-sink-enable').click(function() {
                console.log('Enable/disable sink server.');
                sinkEnable(! sinkEnabled);
                return true;
            });
            $('#btn-copy-code').click(function() {
                console.log('Copy Provision Code to clipboard.');
                copyToClipboard("<?=$agent_uuid;?>");
                return true;
            });
	    $('#btn-copy-code').blur();
        });
    }

    function copyToClipboard(text) {
        var $temp = $("<input>");
        $("body").append($temp);
        $temp.val(text).select();
        document.execCommand("copy");
        $temp.remove();
    }

    function statusRequest() {

        $.ajax(
            "<?=$agent_status_url;?>",
            {
                type: 'get',
                success: agentProvisionUpdate,
                complete: function() {
                    setTimeout(statusRequest, 8000);
                }
            }
        );
    }

    function sinkRequest() {

        $.ajax(
            "<?=$_SERVER['SCRIPT_NAME'];?>",
            {
                type: 'post',
                data: {
                    status: 'update'
                },
                success: agentSinkUpdate,
                complete: function() {
                    setTimeout(sinkRequest, 2000);
                }
            }
        );
    }

    function sinkEnable(enable) {

        $.ajax(
            "<?=$_SERVER['SCRIPT_NAME'];?>",
            {
                type: 'post',
                data: {
                    sinkEnable: enable
                }
            }
        );
    }

    function agentProvisionUpdate(responseData) {
        console.log('agentProvisionUpdate:');
        console.log(responseData);

        if (responseData.status_code != 0) {
            $('#provision-status').html(responseData.status_message);
            $('#provision-status').addClass('text-danger');
            $('#provision-status').removeClass('text-success');
        }
        else if (responseData.data['provisioned'])
            $('#provision-status').html('Provisioned');
        else
            $('#provision-status').html('Not provisioned');

        $('#provision-status').addClass(
            responseData.data['provisioned'] ? 'text-success' : 'text-danger'
        );
        $('#provision-status').removeClass(
            responseData.data['provisioned'] ? 'text-danger' : 'text-success'
        );
    }

    function agentSinkUpdate(responseData) {
        console.log('agentSinkUpdate:');
        console.log(responseData);

        sinkEnabled = responseData['sink_enabled']

        $('#btn-sink-enable').prop('disabled', false);

        if (sinkEnabled) {
            $('#btn-sink-enable').html('Disable');
            $('#btn-sink-enable').addClass('btn-danger');
            $('#btn-sink-enable').removeClass('btn-success');
            $('#sink-warning').hide();
            $('#sink-status').html('Sink Enabled');
        }
        else {
            $('#btn-sink-enable').html('Enable');
            $('#btn-sink-enable').addClass('btn-success');
            $('#btn-sink-enable').removeClass('btn-danger');
            $('#sink-warning').show();
            $('#sink-status').html('Sink Disabled');
        }
    }

    setTimeout(init, 500);
    setTimeout(statusRequest, 1000);
    setTimeout(sinkRequest, 1000);
//]]>
</script>

<?php
include("foot.inc"); ?>
