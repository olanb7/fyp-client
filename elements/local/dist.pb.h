// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: dist.proto

#ifndef PROTOBUF_dist_2eproto__INCLUDED
#define PROTOBUF_dist_2eproto__INCLUDED

#include <string>

#include <google/protobuf/stubs/common.h>

#if GOOGLE_PROTOBUF_VERSION < 2003000
#error This file was generated by a newer version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please update
#error your headers.
#endif
#if 2003000 < GOOGLE_PROTOBUF_MIN_PROTOC_VERSION
#error This file was generated by an older version of protoc which is
#error incompatible with your Protocol Buffer headers.  Please
#error regenerate this file with a newer version of protoc.
#endif

#include <google/protobuf/generated_message_util.h>
#include <google/protobuf/repeated_field.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/generated_message_reflection.h>
// @@protoc_insertion_point(includes)

namespace DIDS {

// Internal implementation detail -- do not call these.
void  protobuf_AddDesc_dist_2eproto();
void protobuf_AssignDesc_dist_2eproto();
void protobuf_ShutdownFile_dist_2eproto();

class Station;
class Instance;

// ===================================================================

class Station : public ::google::protobuf::Message {
 public:
  Station();
  virtual ~Station();
  
  Station(const Station& from);
  
  inline Station& operator=(const Station& from) {
    CopyFrom(from);
    return *this;
  }
  
  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }
  
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }
  
  static const ::google::protobuf::Descriptor* descriptor();
  static const Station& default_instance();
  
  void Swap(Station* other);
  
  // implements Message ----------------------------------------------
  
  Station* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const Station& from);
  void MergeFrom(const Station& from);
  void Clear();
  bool IsInitialized() const;
  
  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:
  
  ::google::protobuf::Metadata GetMetadata() const;
  
  // nested types ----------------------------------------------------
  
  // accessors -------------------------------------------------------
  
  // optional string mac = 2;
  inline bool has_mac() const;
  inline void clear_mac();
  static const int kMacFieldNumber = 2;
  inline const ::std::string& mac() const;
  inline void set_mac(const ::std::string& value);
  inline void set_mac(const char* value);
  inline void set_mac(const char* value, size_t size);
  inline ::std::string* mutable_mac();
  
  // optional int32 beacons = 3;
  inline bool has_beacons() const;
  inline void clear_beacons();
  static const int kBeaconsFieldNumber = 3;
  inline ::google::protobuf::int32 beacons() const;
  inline void set_beacons(::google::protobuf::int32 value);
  
  // repeated int32 rssi = 4;
  inline int rssi_size() const;
  inline void clear_rssi();
  static const int kRssiFieldNumber = 4;
  inline ::google::protobuf::int32 rssi(int index) const;
  inline void set_rssi(int index, ::google::protobuf::int32 value);
  inline void add_rssi(::google::protobuf::int32 value);
  inline const ::google::protobuf::RepeatedField< ::google::protobuf::int32 >&
      rssi() const;
  inline ::google::protobuf::RepeatedField< ::google::protobuf::int32 >*
      mutable_rssi();
  
  // @@protoc_insertion_point(class_scope:DIDS.Station)
 private:
  ::google::protobuf::UnknownFieldSet _unknown_fields_;
  mutable int _cached_size_;
  
  ::std::string* mac_;
  static const ::std::string _default_mac_;
  ::google::protobuf::int32 beacons_;
  ::google::protobuf::RepeatedField< ::google::protobuf::int32 > rssi_;
  friend void  protobuf_AddDesc_dist_2eproto();
  friend void protobuf_AssignDesc_dist_2eproto();
  friend void protobuf_ShutdownFile_dist_2eproto();
  
  ::google::protobuf::uint32 _has_bits_[(3 + 31) / 32];
  
  // WHY DOES & HAVE LOWER PRECEDENCE THAN != !?
  inline bool _has_bit(int index) const {
    return (_has_bits_[index / 32] & (1u << (index % 32))) != 0;
  }
  inline void _set_bit(int index) {
    _has_bits_[index / 32] |= (1u << (index % 32));
  }
  inline void _clear_bit(int index) {
    _has_bits_[index / 32] &= ~(1u << (index % 32));
  }
  
  void InitAsDefaultInstance();
  static Station* default_instance_;
};
// -------------------------------------------------------------------

class Instance : public ::google::protobuf::Message {
 public:
  Instance();
  virtual ~Instance();
  
  Instance(const Instance& from);
  
  inline Instance& operator=(const Instance& from) {
    CopyFrom(from);
    return *this;
  }
  
  inline const ::google::protobuf::UnknownFieldSet& unknown_fields() const {
    return _unknown_fields_;
  }
  
  inline ::google::protobuf::UnknownFieldSet* mutable_unknown_fields() {
    return &_unknown_fields_;
  }
  
  static const ::google::protobuf::Descriptor* descriptor();
  static const Instance& default_instance();
  
  void Swap(Instance* other);
  
  // implements Message ----------------------------------------------
  
  Instance* New() const;
  void CopyFrom(const ::google::protobuf::Message& from);
  void MergeFrom(const ::google::protobuf::Message& from);
  void CopyFrom(const Instance& from);
  void MergeFrom(const Instance& from);
  void Clear();
  bool IsInitialized() const;
  
  int ByteSize() const;
  bool MergePartialFromCodedStream(
      ::google::protobuf::io::CodedInputStream* input);
  void SerializeWithCachedSizes(
      ::google::protobuf::io::CodedOutputStream* output) const;
  ::google::protobuf::uint8* SerializeWithCachedSizesToArray(::google::protobuf::uint8* output) const;
  int GetCachedSize() const { return _cached_size_; }
  private:
  void SharedCtor();
  void SharedDtor();
  void SetCachedSize(int size) const;
  public:
  
  ::google::protobuf::Metadata GetMetadata() const;
  
  // nested types ----------------------------------------------------
  
  // accessors -------------------------------------------------------
  
  // repeated .DIDS.Station station = 1;
  inline int station_size() const;
  inline void clear_station();
  static const int kStationFieldNumber = 1;
  inline const ::DIDS::Station& station(int index) const;
  inline ::DIDS::Station* mutable_station(int index);
  inline ::DIDS::Station* add_station();
  inline const ::google::protobuf::RepeatedPtrField< ::DIDS::Station >&
      station() const;
  inline ::google::protobuf::RepeatedPtrField< ::DIDS::Station >*
      mutable_station();
  
  // @@protoc_insertion_point(class_scope:DIDS.Instance)
 private:
  ::google::protobuf::UnknownFieldSet _unknown_fields_;
  mutable int _cached_size_;
  
  ::google::protobuf::RepeatedPtrField< ::DIDS::Station > station_;
  friend void  protobuf_AddDesc_dist_2eproto();
  friend void protobuf_AssignDesc_dist_2eproto();
  friend void protobuf_ShutdownFile_dist_2eproto();
  
  ::google::protobuf::uint32 _has_bits_[(1 + 31) / 32];
  
  // WHY DOES & HAVE LOWER PRECEDENCE THAN != !?
  inline bool _has_bit(int index) const {
    return (_has_bits_[index / 32] & (1u << (index % 32))) != 0;
  }
  inline void _set_bit(int index) {
    _has_bits_[index / 32] |= (1u << (index % 32));
  }
  inline void _clear_bit(int index) {
    _has_bits_[index / 32] &= ~(1u << (index % 32));
  }
  
  void InitAsDefaultInstance();
  static Instance* default_instance_;
};
// ===================================================================


// ===================================================================

// Station

// optional string mac = 2;
inline bool Station::has_mac() const {
  return _has_bit(0);
}
inline void Station::clear_mac() {
  if (mac_ != &_default_mac_) {
    mac_->clear();
  }
  _clear_bit(0);
}
inline const ::std::string& Station::mac() const {
  return *mac_;
}
inline void Station::set_mac(const ::std::string& value) {
  _set_bit(0);
  if (mac_ == &_default_mac_) {
    mac_ = new ::std::string;
  }
  mac_->assign(value);
}
inline void Station::set_mac(const char* value) {
  _set_bit(0);
  if (mac_ == &_default_mac_) {
    mac_ = new ::std::string;
  }
  mac_->assign(value);
}
inline void Station::set_mac(const char* value, size_t size) {
  _set_bit(0);
  if (mac_ == &_default_mac_) {
    mac_ = new ::std::string;
  }
  mac_->assign(reinterpret_cast<const char*>(value), size);
}
inline ::std::string* Station::mutable_mac() {
  _set_bit(0);
  if (mac_ == &_default_mac_) {
    mac_ = new ::std::string;
  }
  return mac_;
}

// optional int32 beacons = 3;
inline bool Station::has_beacons() const {
  return _has_bit(1);
}
inline void Station::clear_beacons() {
  beacons_ = 0;
  _clear_bit(1);
}
inline ::google::protobuf::int32 Station::beacons() const {
  return beacons_;
}
inline void Station::set_beacons(::google::protobuf::int32 value) {
  _set_bit(1);
  beacons_ = value;
}

// repeated int32 rssi = 4;
inline int Station::rssi_size() const {
  return rssi_.size();
}
inline void Station::clear_rssi() {
  rssi_.Clear();
}
inline ::google::protobuf::int32 Station::rssi(int index) const {
  return rssi_.Get(index);
}
inline void Station::set_rssi(int index, ::google::protobuf::int32 value) {
  rssi_.Set(index, value);
}
inline void Station::add_rssi(::google::protobuf::int32 value) {
  rssi_.Add(value);
}
inline const ::google::protobuf::RepeatedField< ::google::protobuf::int32 >&
Station::rssi() const {
  return rssi_;
}
inline ::google::protobuf::RepeatedField< ::google::protobuf::int32 >*
Station::mutable_rssi() {
  return &rssi_;
}

// -------------------------------------------------------------------

// Instance

// repeated .DIDS.Station station = 1;
inline int Instance::station_size() const {
  return station_.size();
}
inline void Instance::clear_station() {
  station_.Clear();
}
inline const ::DIDS::Station& Instance::station(int index) const {
  return station_.Get(index);
}
inline ::DIDS::Station* Instance::mutable_station(int index) {
  return station_.Mutable(index);
}
inline ::DIDS::Station* Instance::add_station() {
  return station_.Add();
}
inline const ::google::protobuf::RepeatedPtrField< ::DIDS::Station >&
Instance::station() const {
  return station_;
}
inline ::google::protobuf::RepeatedPtrField< ::DIDS::Station >*
Instance::mutable_station() {
  return &station_;
}


// @@protoc_insertion_point(namespace_scope)

}  // namespace DIDS

#ifndef SWIG
namespace google {
namespace protobuf {


}  // namespace google
}  // namespace protobuf
#endif  // SWIG

// @@protoc_insertion_point(global_scope)

#endif  // PROTOBUF_dist_2eproto__INCLUDED