#include <click/config.h>
#include "staTest.hh"
#include <click/element.hh>
#include <click/timer.hh>
#include <clicknet/ether.h>
#include <click/etheraddress.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/wifi.h>
#include <click/etheraddress.hh>
#include <click/confparse.hh>
#include <click/vector.hh>
#include <elements/wifi/availablerates.hh>
#include <elements/wifi/wirelessinfo.hh>
#include <click/list.hh>
#include <click/error.hh>
#include <string>
#include <click/ewma.hh>  	// !!
#include <click/error.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/packet_anno.hh>
#include <click/straccum.hh>
#include <clicknet/wifi.h>
#include "dist.pb.cc"
#if CLICK_USERLEVEL
# include <sys/time.h>
# include <sys/resource.h>
# include <unistd.h>
#endif

#define show_debug 0		// output debug messages from getStats funcion
#define window 100 		// define window size in packets

CLICK_DECLS

StaTest::StaTest()
  : _timer(this),
    _logfile(0)
{
}

StaTest::~StaTest()
{
}

int
StaTest::initialize (ErrorHandler *) {

	_timer.initialize(this);
	_timer.schedule_after_sec(1);
	return 0;
}

void StaTest::run_timer(Timer *) {

	getStats(_sta_list);
	//printStations(_sta_list);

	output(0).push(make_packet(stationlog));
	cleanup(_sta_list);
	log.clear();
	
	_timer.schedule_after_msec(1000);
}



void StaTest::cleanup (StationList &l) {

	for (StationList::iterator sta = l.begin(); sta != l.end(); ++sta) {

		sta->flag = 1;
		sta->shortVar_flag = 0;
		//sta->beacon_rate = 0;
		sta->jitter = 0;
		sta->salvaged = 0;
		goodcrc = 0;
		badcrc = 0;
	}
	
	for(int i = 0; i < stationlog.station_size(); i++) {
		stationlog.mutable_station(i)->clear_rssi();
		stationlog.mutable_station(i)->clear_beacons();
	}
}

StaTest::station *
StaTest::lookup(station &chksta, StationList &l) {
	size_t n = 0;
	for (StationList::iterator lkup = l.begin(); lkup != l.end(); ++lkup, ++n) {

		// if MAC address is found in list, return pointer to it
		if(!strcmp(chksta.mac->unparse().c_str(), lkup->mac->unparse().c_str())) {
				return lkup.get();
		}
	}
	return (struct station*)NULL;
}



void StaTest::getStats (StationList &l) {
	
	//int error = 1; // beacon per second error
	
	for (StationList::iterator sta = l.begin(); sta != l.end(); ++sta) {

		debug << "\n" << sta->mac->unparse().c_str();
		getAverage(*sta, 100);

		if (sta->past_beacons.size() >= window) {
			sta->past_beacons.pop_front();
		}
		// put new rssi in array
		sta->past_beacons.push_back(sta->beacon_rate);

		getBeaconAverage(*sta, 3);
	}

}

void StaTest::getAverage(station &sta, int samples) {

	sta.ave = 0;
	if (sta.past_packets.size() < samples)
		samples = sta.past_packets.size();

	int start = sta.past_packets.size() - samples;

	debug << "\ngetAverage: ";

	if (!sta.past_packets.empty()) {
		for(int i = start; i < sta.past_packets.size(); i++) {
			debug << sta.past_packets.at(i) << " + ";
			sta.ave += sta.past_packets.at(i);
		}
		sta.ave = sta.ave / samples;
	}
	else {
		sta.ave = 0;
	}
	debug << " -> average = " << sta.ave;
}

void StaTest::getBeaconAverage(station &sta, int samples) {

	sta.beacon_ave = 0;
	if (sta.past_beacons.size() < samples)
		samples = sta.past_beacons.size();

	int start = sta.past_beacons.size() - samples;

	debug << "\ngetBeaconAverage: ";

	if (!sta.past_beacons.empty()) {
		for(int i = start; i < sta.past_beacons.size(); i++) {
			debug << sta.past_beacons.at(i) << " + ";
			sta.beacon_ave += sta.past_beacons.at(i);
		}
		sta.beacon_ave = sta.beacon_ave / samples;
	}
	else {
		sta.beacon_ave = sta.beacon_rate;
	}
	debug << " -> BeaconAverage = " << sta.beacon_ave;
}


void StaTest::keepTrack(station &sta){

	// put new rssi in array
	sta.past_packets.push_back(sta.rssi);

	if (sta.past_packets.size() >= window) {
		sta.past_packets.pop_front();
	}	
}


void 
StaTest::logOutput(station &sta, StringAccum log) {

	StringAccum fn;

	// log packets to file
	fn << "/home/olan/logs/" << sta.mac->unparse().c_str() << "-client.txt";
	_filename = fn.take_string();

	if (_filename) {
		_logfile = fopen(_filename.c_str(), "a");
		if (!_logfile)
			click_chatter("ERROR: %s, can't open logfile for appending\n", _filename.c_str());

		fwrite(log.data(), 1, log.length(), _logfile);
	}
	else {
		click_chatter("Wrong filename : %s\n", _filename.c_str());	
	}

  	if (_logfile)
  		fclose(_logfile);
	_logfile = 0;
}

Packet *
StaTest::make_packet(DIDS::Instance &packetData)
{
   
    //click_chatter("%s", packetData.c_str());
 
    std::string protoOutput = std::string();
    packetData.SerializeToString(&protoOutput);

    //click_chatter("proto before: %d bytes\t proto after: %d bytes", sizeof(packetData), sizeof(protoOutput));

    WritablePacket *q = Packet::make(sizeof(click_ip)+sizeof(click_tcp)+sizeof(click_ether)+sizeof(protoOutput),protoOutput.data(),protoOutput.length(),0);

    return q;
}


void
StaTest::push(int, Packet *p) {

	GOOGLE_PROTOBUF_VERIFY_VERSION;

	StringAccum dir;

	struct click_wifi *w = (struct click_wifi *) p->data();
	struct click_wifi_extra *ceha = WIFI_EXTRA_ANNO(p);

	struct station *sta = new station;

	int pktType = w->i_fc[0] & WIFI_FC0_TYPE_MASK;
	int subtype = w->i_fc[0] & WIFI_FC0_SUBTYPE_MASK;

	int isBeacon = 0;
	
	// Check failed CRC
	if (ceha->flags & WIFI_EXTRA_RX_MORE) {                         // No CRC               
		click_chatter("no crc");
                p->kill();
                goto end;
		//return;
        } else if (ceha->flags & WIFI_EXTRA_RX_ERR) {                  // Failed CRC
                click_chatter("failed crc");
		p->kill();
                goto end;
		//return;
        }

	// Check DS Status
	switch (w->i_fc[1] & WIFI_FC1_DIR_MASK) {
		case WIFI_FC1_DIR_NODS:
			sta->dst = new EtherAddress(w->i_addr1);
			sta->src = new EtherAddress(w->i_addr2);
			sta->mac = new EtherAddress(w->i_addr3);
			dir << "NoDS  ";
			break;
		case WIFI_FC1_DIR_TODS:
			sta->mac = new EtherAddress(w->i_addr1);	// not interested in ToDS
			sta->dst = new EtherAddress(w->i_addr1);	// as gives bad results
			sta->src = new EtherAddress(w->i_addr2);	// using two wireless cards 
			dir << "ToDS  ";
			break;
		case WIFI_FC1_DIR_FROMDS:
			sta->mac = new EtherAddress(w->i_addr2);
			sta->dst = new EtherAddress(w->i_addr1);
			sta->src = new EtherAddress(w->i_addr2);
			dir << "FromDS";
			break;
		case WIFI_FC1_DIR_DSTODS:
			sta->mac = new EtherAddress(w->i_addr3);
			sta->dst = new EtherAddress(w->i_addr1);
			sta->src = new EtherAddress(w->i_addr2);
			dir << "DStoDS";
			break;
		default:
			goto push;
	}

	switch (pktType) {								
		case WIFI_FC0_TYPE_DATA:
			sta->type = 1;
			sta->mac = sta->src;
			break;
		case WIFI_FC0_TYPE_MGT:
			switch (subtype) {
				case WIFI_FC0_SUBTYPE_BEACON:
					isBeacon = 1;
					break;
				case WIFI_FC0_SUBTYPE_ASSOC_RESP:
				case WIFI_FC0_SUBTYPE_REASSOC_RESP:
				case WIFI_FC0_SUBTYPE_PROBE_RESP:
					sta->type = 0;
					break;
				case WIFI_FC0_SUBTYPE_PROBE_REQ:
					sta->type = 1;
					sta->mac = sta->src;
					break;
				default:
					sta->type = 2;
					
			}
			break;
		default:
			goto push;
	}

	// get packet rssi	
	sta->rssi = ceha->rssi;

	if (!_sta_list.empty()) {
	// list not empty, so lookup
		
		struct station *duplicate = lookup(*sta, _sta_list);
		
		if (duplicate) {					
		// if station is already in list, update it 
			
			duplicate->time->set_now();
			duplicate->rssi = sta->rssi;

			keepTrack(*duplicate);

			// Output to logfile in format: MAC | Time | Type | RSSI [PROB NOT NEEDED]
			//log << *duplicate->mac  << "\t";
			log << *duplicate->time	<< "\t";
			//log <<  duplicate->type << "\t";
			log <<  duplicate->rssi	<< "\t";

			if(stationlog.station_size() == 0) {
				click_chatter("ERROR: No protobuf stations but click says dupe");
			}
			
			// loop to search through stationlog (the protobuf list) and add rssi to stations (MAC) seen before 
			// !MUST BE BETTER METHOD - IDENTIFY STATION IN LIST!
			for(int k = 0; k < stationlog.station_size(); k++) {

				DIDS::Station* station_iter = stationlog.mutable_station(k);
				
				if (strcmp(station_iter->mac().c_str(), duplicate->mac->unparse().c_str()) == 0) {
				 	station_iter->add_rssi(duplicate->rssi);
				 	
				 	if (isBeacon == 1) {
				 		station_iter->set_beacons(station_iter->beacons()+1);
				 	}
				}
			}
			
			
		}
		else {
		// else if station is not in list, add it		 
		 
			sta->time = new Timestamp(Timestamp::now());
			sta->first_run = 1;

			//log << *sta->mac  << "\t";
			log << *sta->time << "\t";
			//log <<  sta->type << "\t";
			log <<  sta->rssi << "\t";

			DIDS::Station* station = stationlog.add_station();
			station->set_mac(sta->mac->unparse().c_str());
			station->add_rssi(sta->rssi);
			station->set_beacons(1);
			_sta_list.push_back(sta);

		 }
	}
	else {					
	// list is empty so add
	
		sta->time = new Timestamp(Timestamp::now());
		sta->first_run = 1;

		//log << *sta->mac  << "\t";
		log << *sta->time << "\t";
		//log <<  sta->type << "\t";
		log <<  sta->rssi << "\t";

		DIDS::Station* station = stationlog.add_station();
		station->set_mac(sta->mac->unparse().c_str());
		station->add_rssi(sta->rssi);
		station->set_beacons(1);

		_sta_list.push_back(sta);
	}

	log << "\n";
	
	#if CLICK_USERLEVEL
		logOutput(*sta, log);
	#endif

	log.clear();
	
	push:
	//google::protobuf::ShutdownProtobufLibrary();

	// need to create another element output
	//output(0).push(p);

	end:
	google::protobuf::ShutdownProtobufLibrary();
	// do nothing
}



EXPORT_ELEMENT(StaTest)
CLICK_ENDDECLS
ELEMENT_LIBS((-L/usr/local/lib -lprotobuf))


