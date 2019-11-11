<?php
require_once('guiconfig.inc');
require_once('/usr/local/pkg/netify/netify.inc');

if ($_POST['status'] == 'update') {
	$status = array(
		'version' => NETIFYD_VERSION,
		'running' => netifyd_is_running(),
		'status' => array()
	);

	if (file_exists(NETIFYD_JSON_STATUS)) {
		$status['status'] = json_decode(
			file_get_contents(NETIFYD_JSON_STATUS)
		);

		if ($status['status']->sink_status)
			$status['status']->sink_status = gettext('Yes');
		else
			$status['status']->sink_status = gettext('No');

		if ($status['status']->dhc_status)
			$status['status']->dhc_status = gettext('Enabled');
		else
			$status['status']->dhc_status = gettext('Disabled');

		switch ($status['status']->sink_resp_code) {
		case 1:
			$resp_text = sprintf('%s (%d)',
				gettext('Ok'),
				$status['status']->sink_resp_code);
			break;
		case 2:
			$resp_text = sprintf('%s (%d)',
				gettext('Authorization failure'),
				$status['status']->sink_resp_code);
			break;
		case 3:
			$resp_text = sprintf('%s (%d)',
				gettext('Malformed update data'),
				$status['status']->sink_resp_code);
			break;
		case 4:
			$resp_text = sprintf('%s (%d)',
				gettext('Server error'),
				$status['status']->sink_resp_code);
			break;
		case 5:
			$resp_text = sprintf('%s (%d)',
				gettext('Upload error'),
				$status['status']->sink_resp_code);
			break;
		case 6:
			$resp_text = sprintf('%s (%d)',
				gettext('Parse error'),
				$status['status']->sink_resp_code);
			break;
		case 7:
			$resp_text = sprintf('%s (%d)',
				gettext('Invalid response'),
				$status['status']->sink_resp_code);
			break;
		case 7:
			$resp_text = sprintf('%s (%d)',
				gettext('Invalid response content type'),
				$status['status']->sink_resp_code);
			break;
		default:
			$resp_text = sprintf('%s (%d)',
				gettext('Unknown'),
				$status['status']->sink_resp_code);
		}

		$status['status']->sink_resp_code = $resp_text;
	}
	else {
		$status['error'] = 'Agent status file not found.';
	}

	$response = json_encode($status);
	header('Content-Type: application/json');
	header('Content-Length: ' . strlen($response));

	echo json_encode($status);

	exit;
}

$pgtitle = array(gettext('Services'), gettext('Netify'), gettext('Status'));
include_once("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("Status"), true, "/netify/netify_status.php");
$tab_array[] = array(gettext("Provision"), false, "/netify/netify_provision.php");

display_top_tabs($tab_array, true);

?>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext("Netify Agent Status")?></h2>
	</div>
	<div class="panel-body">
		<div class="content table-responsive">
			<table id="maintable" class="table table-striped table-hover table-condensed">
				<tr>
					<th>Version</th>
					<td id="agent_version"></td>
					<th>Status</th>
					<td id="agent_status">Unknown</td>
				</tr>
				<tr>
					<th>Last Update</th>
					<td id="agent_timestamp"></td>
					<th>Uptime</th>
					<td id="agent_uptime"></td>
				</tr>
				<tr>
					<th>Sink Enabled</th>
					<td id="agent_sink_status"></td>
					<th>Sink Status</th>
					<td id="agent_sink_resp_code"></td>
				</tr>
				<tr>
					<th>Sink Queue Size</th>
					<td id="agent_sink_queue_size"></td>
					<th>Sink Queue Maximum Size</th>
					<td id="agent_sink_queue_max_size"></td>
				</tr>
				<tr>
					<th>Flows</th>
					<td id="agent_flows"></td>
					<th>Flows Delta</th>
					<td id="agent_flows_delta"></td>
				</tr>
				<tr>
					<th>DNS Hint Caching</th>
					<td id="agent_dhc_status"></td>
					<th>DNS Hint Cache Entries</th>
					<td id="agent_dhc_size"></td>
				</tr>
				<tr>
					<th>Maximum RSS Memory</th>
					<td id="agent_maxrss"></td>
					<th>RSS Delta</th>
					<td id="agent_maxrss_delta"></td>
				</tr>
			</table>
		</div>
	</div>
</div>

<script type="text/javascript">
//<![CDATA[

	function statusRequest() {

		$.ajax(
			"<?=$_SERVER['SCRIPT_NAME'];?>",
			{
				type: 'post',
				data: {
					status: 'update'
				},
				success: statusUpdate,
				complete: function() {
					setTimeout(statusRequest, 2000);
				}
			}
		);
	}

	function uptime(seconds) {
		var days = 0, hours = 0, minutes = 0;

		if (seconds >= 86400) {
			days = Math.floor(seconds / 86400);
			seconds -= days * 86400;
		}

		if (seconds >= 3600) {
			hours = Math.floor(seconds / 3600);
			seconds -= hours * 3600;
		}

		if (seconds >= 60) {
			minutes = Math.floor(seconds / 60);
			seconds -= minutes * 60;
		}

		return days.toString().padStart(2, '0') + 'd ' +
			hours.toString().padStart(2, '0') + ':' +
			minutes.toString().padStart(2, '0') + ':' +
			seconds.toString().padStart(2, '0');
	}

	function statusUpdate(responseData) {
		/*
		{
		  "type": "agent_status",
		  "timestamp": 1573494902,
		  "uptime": 540,
		  "flows": 55,
		  "flows_prev": 35,
		  "maxrss_kb": 42308,
		  "maxrss_kb_prev": 42300,
		  "dhc_status": true,
		  "dhc_size": 16,
		  "sink_status": true,
		  "sink_queue_size_kb": 0,
		  "sink_queue_max_size_kb": 2048,
		  "sink_resp_code": 1
		}
		*/
		console.log('statusUpdate:');

		for(var key in responseData.status) {
			console.log(
				'key: ' + key +
				', value: ' + responseData.status[key]
			);
		}

		$('#agent_version').html('v' + responseData.version);
		$('#agent_status').html(responseData.running ? 'Running' : 'Stopped');
		$('#agent_status').addClass(
			responseData.running ? 'text-success' : 'text-danger'
		);
		$('#agent_status').removeClass(
			responseData.running ? 'text-danger' : 'text-success'
		);
		var timestamp = new Date(responseData.status['timestamp'] * 1000);
		$('#agent_timestamp').html(timestamp.toLocaleString());
		$('#agent_uptime').html(uptime(responseData.status['uptime']));
		$('#agent_sink_status').html(responseData.status['sink_status']);
		$('#agent_sink_resp_code').html(responseData.status['sink_resp_code']);
		var sink_queue_percentage =
			responseData.status['sink_queue_size_kb'] * 100 /
			responseData.status['sink_queue_max_size_kb'];
		var sink_queue_percentage_options = {
			'style': 'percent',
			'minimumFractionDigits': 2,
			'maximumFractionDigits': 2
		};
		$('#agent_sink_queue_size').html(
			responseData.status['sink_queue_size_kb'].toLocaleString() + ' kB (' +
			sink_queue_percentage.toLocaleString('en-US',
				sink_queue_percentage_options) + ')'
		);
		$('#agent_sink_queue_size').addClass(
			sink_queue_percentage < 50 ? 'text-success' : 'text-danger'
		);
		$('#agent_sink_queue_size').removeClass(
			sink_queue_percentage >= 50 ? 'text-success' : 'text-danger'
		);
		$('#agent_sink_queue_max_size').html(
			responseData.status['sink_queue_max_size_kb'].toLocaleString() + ' kB'
		);
		$('#agent_flows').html(responseData.status['flows'].toLocaleString());
		$('#agent_flows_delta').html(
			(responseData.status['flows'] - 
			responseData.status['flows_prev']).toLocaleString()
		);
		$('#agent_maxrss').html(
			responseData.status['maxrss_kb'].toLocaleString() + ' kB'
		);
		$('#agent_maxrss_delta').html(
			(responseData.status['maxrss_kb'] - 
			responseData.status['maxrss_kb_prev']).toLocaleString() +
			' kB'
		);
		$('#agent_dhc_status').html(responseData.status['dhc_status']);
		$('#agent_dhc_size').html(
			responseData.status['dhc_size'].toLocaleString()
		);
	}

	setTimeout(statusRequest, 1000);
//]]>
</script>

<?php
include("foot.inc");
?>
