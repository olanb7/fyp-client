#ifndef CLICK_SETTXRATE_HH
#define CLICK_SETTXRATE_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <elements/wifi/autotxrate.hh>
CLICK_DECLS

/*
 * =c
 * 
 * SetTXRate(RATE, [, I<KEYWORDS>])
 * 
 * =s wifi
 * 
 * Sets the Wifi TXRate Annotation on a packet.
 * 
 * Regular Arguments:
 * =over 8
 *
 * =item RATE
 * 
 * Unsigned integer. Valid rates are 1, 2, 5, and 11.
 *
 * =back
 *
 *  Keywords arguments:
 *
 * =item AUTO
 * 
 * AutoTXRate element.  When used in conjunction with this 
 * element, settxrate will autoscale the rate.
 *
 */

class SetTXRate : public Element { public:
  
  SetTXRate();
  ~SetTXRate();
  
  const char *class_name() const		{ return "SetTXRate"; }
  const char *processing() const		{ return AGNOSTIC; }
  
  SetTXRate *clone() const;
  int configure(Vector<String> &, ErrorHandler *);
  bool can_live_reconfigure() const		{ return true; }

  Packet *simple_action(Packet *);

  void add_handlers();
  static String rate_read_handler(Element *e, void *);
  static String auto_read_handler(Element *e, void *);  
 private:
  
  int _rate;
  class AutoTXRate *_auto;
};

CLICK_ENDDECLS
#endif