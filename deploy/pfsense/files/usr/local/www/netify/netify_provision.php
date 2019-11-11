<?php
require_once('guiconfig.inc');
require_once('/usr/local/pkg/netify/netify.inc');

if ($_POST['status'] == 'update') {
	$status = array('uuid' => '00-00-00-00');
	$status = array('provisioned' => false);

	$response = json_encode($status);
	header('Content-Type: application/json');
	header('Content-Length: ' . strlen($response));

	echo json_encode($status);

	exit;
}

include('head.inc');
$pgtitle = array(gettext('Services'), gettext('Netify'), gettext('Provision'));

$tab_array = array();
$tab_array[] = array(gettext('Status'), false, '/netify/netify_status.php');
$tab_array[] = array(gettext('Provision'), true, '/netify/netify_provision.php');

display_top_tabs($tab_array, true);

$agent_uuid = netifyd_get_uuid();
$agent_status_url = netifyd_get_agent_status_url();

?>

<form>
	<div class="panel panel-default">
		<div class="panel-heading">
			<h2 class="panel-title">
				<?=gettext("Netify Agent Provisioning")?>
			</h2>
		</div>
		<div class="panel-body">
			<div class="content table-responsive">
				<table class="table table-striped table-hover table-condensed">
					<tr>
						<th style='text-align: right; vertical-align: middle;'>Provision Code</th>
						<td><input type="text" value="<?=$agent_uuid;?>" readonly></td>
						<th style='text-align: right; vertical-align: middle;'>Status</th>
						<td><input id="provision-status" type="text" value="<?=gettext('Loading...');?>" readonly></td>
					</tr>
					<tr>
						<td colspan="4" style='text-align: right;'>
							<button id="btn-provision" class="btn btn-success" type="button" title="<?=gettext('Provision Agent on Netify Portal'); ?>">Provision Netify Agent</button>
						</td>
					</tr>
				</table>
			</div>
		</div>
	</div>
</form>

<script type="text/javascript">
//<![CDATA[
	function init() {
		$(document).ready(function() {
			console.log('DOM ready.');
			$('#btn-provision').click(function() {
				console.log('Provision clicked.');
				window.open('http://netify.ai/get-netify');
				return false;
			});
		});
	}

	function statusRequest() {

		$.ajax(
			"<?=$agent_status_url;?>",
			{
				type: 'get',
				success: agentProvisionUpdate,
				complete: function() {
					setTimeout(statusRequest, 3000);
				}
			}
		);
	}

	function agentProvisionUpdate(responseData) {
		console.log('agentProvisionUpdate:');
		console.log(responseData);

		if (responseData.status_code != 0) {
			$('#provision-status').val(responseData.status_message);
			$('#provision-status').addClass('text-danger');
			$('#provision-status').removeClass('text-success');
		}
		else if (responseData.data['provisioned'])
			$('#provision-status').val('Provisioned');
		else
			$('#provision-status').val('Not provisioned');

		$('#provision-status').addClass(
			responseData.data['provisioned'] ? 'text-success' : 'text-danger'
		);
		$('#provision-status').removeClass(
			responseData.data['provisioned'] ? 'text-danger' : 'text-success'
		);
	}

	setTimeout(init, 500);
	setTimeout(statusRequest, 1000);
//]]>
</script>

<?php
include("foot.inc"); ?>
