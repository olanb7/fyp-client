#ifndef ETXMETRIC_HH
#define ETXMETRIC_HH
#include <click/element.hh>
#include "gridgenericmetric.hh"
CLICK_DECLS

/*
 * =c
 * ETXMetric(LinkStat)
 * =s Grid
 * =io
 * None
 * =d
 *
 * LinkStat is this node's LinkStat element.  The LinkStat loss-rate
 * information is used to calculate the ETX metric.
 *
 * Child class of GridGenericMetric that implements the estimate transmission count (`ETX') metric.
 * =a HopcountMetric, LinkStat */

class LinkStat;

class ETXMetric : public GridGenericMetric {
  
public:

  ETXMetric();
  ~ETXMetric();

  const char *class_name() const { return "ETXMetric"; }
  const char *processing() const { return AGNOSTIC; }
  ETXMetric *clone()  const { return new ETXMetric; } 

  int configure(Vector<String> &, ErrorHandler *);
  bool can_live_reconfigure() const { return false; }

  void add_handlers();

  void *cast(const char *);

  // generic metric methods
  bool metric_val_lt(const metric_t &, const metric_t &) const;
  metric_t get_link_metric(const EtherAddress &n) const;
  metric_t append_metric(const metric_t &, const metric_t &) const;

private:
  LinkStat *_ls;
};

CLICK_ENDDECLS
#endif