#ifndef HCMETRIC_HH
#define HCMETRIC_HH
#include <click/element.hh>
#include "gridgenericmetric.hh"
CLICK_DECLS

/*
 * =c
 * HopcountMetric
 * =s Grid
 * =io
 * None
 * =d
 *
 * Child class of GridGenericMetric that implements the minimum hop-count metric.
 * =a ETXMetric
 */
class HopcountMetric : public GridGenericMetric {
  
public:

  HopcountMetric();
  ~HopcountMetric();

  const char *class_name() const { return "HopcountMetric"; }
  const char *processing() const { return AGNOSTIC; }
  HopcountMetric *clone()  const { return new HopcountMetric; } 

  int configure(Vector<String> &, ErrorHandler *);
  bool can_live_reconfigure() const { return false; }

  void add_handlers();

  void *cast(const char *);

  // generic metric methods
  bool metric_val_lt(const metric_t &, const metric_t &) const;
  metric_t get_link_metric(const EtherAddress &n) const;
  metric_t append_metric(const metric_t &, const metric_t &) const;

};

CLICK_ENDDECLS
#endif