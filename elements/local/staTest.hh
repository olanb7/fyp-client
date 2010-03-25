#ifndef CLICK_STATEST_HH
#define CLICK_STATEST_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <clicknet/ether.h>
#include <click/etheraddress.hh>
#include <click/dequeue.hh>
#include <clicknet/wifi.h>
#include <click/etheraddress.hh>
#include <click/confparse.hh>
#include <click/glue.hh>
#include <clicknet/llc.h>
#include <click/straccum.hh>
#include <click/vector.hh>
#include <click/hashmap.hh>
#include <click/packet_anno.hh>
#include <elements/wifi/availablerates.hh>
#include <elements/wifi/wirelessinfo.hh>
#include <click/list.hh>
#include <click/error.hh>
#include <click/crc32.h>
#include <click/bighashmap.hh>
#if CLICK_USERLEVEL
# include <sys/time.h>
# include <sys/resource.h>
# include <unistd.h>
#endif
#include <click/ewma.hh>
#include "dist.pb.h"

CLICK_DECLS

class StaTest : public Element {

public:

  StaTest();
  ~StaTest();

  typedef DirectEWMAX<FixedEWMAXParameters<3, 10, uint64_t, int64_t> > ewma_type;

  struct station {
	EtherAddress *mac, *dst, *src;
	Timestamp *time;

	List_member<station> link;

	Vector<int> past_packets;
	Vector<int> past_beacons;

	double ave, longVar, shortVar, beacon_ave;
	int rssi, beacon_rate, type;
	int flag, first_run, seen;
	int badcrc, goodcrc, salvaged;						// flags
	int beacon_attack, var_attack_high, var_attack_low, shortVar_flag;	// attack flags
	uint16_t beacon_int; 
	uint32_t jitter, avg_jitter;
	u_int64_t mactime;
	ewma_type _ewma;
	};

 
  typedef List<station, &station::link> StationList;
  StationList _sta_list;

  const char *class_name() const	{ return "StaTest"; }
  const char *port_count() const	{ return PORTS_1_1; }
  const char *processing() const	{ return PUSH; }
  
  void push (int port, Packet *);
  int  initialize (ErrorHandler *);
  void keepTrack (station &);
  void logOutput (station &, StringAccum);
  void run_timer (Timer *);
  void printStations (StationList &l);
  void cleanup (StationList &l);
  void getStats (StationList &l);
  void getAverage (station &, int);
  void getBeaconAverage (station &, int);
  void getEWMA (station &);
  void getLongVariance (station &, int);
  void getShortVariance (station &, int);
  Packet * make_packet (DIDS::Instance &);
  

  StaTest::station * lookup(station &, StationList &);

  // declare protobuf member
  //DIDS::Instance instance;
	DIDS::Instance stationlog;
  
  Timer  _timer;
  String _filename, protoOut;
  FILE  *_logfile; 
  StringAccum debug, log;
  int badcrc, goodcrc, salvaged;

};
CLICK_ENDDECLS
#endif
