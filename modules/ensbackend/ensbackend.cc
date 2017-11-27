#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "pdns/utility.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/version.hh"
#include "pdns/zoneparser-tng.hh"
#include <boost/algorithm/string.hpp>

/* FIRST PART */
class EnsBackend : public DNSBackend
{
public:
  EnsBackend(const string &suffix="")
  {
    setArgPrefix("ens"+suffix);
    d_connection = getArg("connection");
    d_types = {};
    d_records = {};

    // TODO connect to Ethereum

  }

  bool list(const DNSName &target, int id, bool include_disabled) override {
    return false; // we don't support AXFR
  }

  void lookup(const QType &type, const DNSName &qdomain, DNSPacket *p, int zoneId) override
  {
    L<<Logger::Info<<"[lookup] looking for "<<type.getName()<<"@"<<qdomain<<endl;
    if (type.getCode() == QType::ANY) {
      // Loop for all of the items we care about
      // TODO any other types?
      this->lookup(QType(QType::SOA), qdomain, p, zoneId);
      this->lookup(QType(QType::NS), qdomain, p, zoneId);
      this->lookup(QType(QType::MX), qdomain, p, zoneId);
      this->lookup(QType(QType::TXT), qdomain, p, zoneId);
      this->lookup(QType(QType::CNAME), qdomain, p, zoneId);
      this->lookup(QType(QType::A), qdomain, p, zoneId);
      this->lookup(QType(QType::AAAA), qdomain, p, zoneId);
      return;
    }

    // Individual record type; set up our parameters
    string ethResource = type.getName();
    string ethDomain;
    string ethKey;

    // First attempt is to try with the full domain and a key of '.'
    ethDomain = qdomain.toString();
    ethKey = ".";
    if (ethDomain.size() > 1) {
      ethDomain.erase(ethDomain.size()-1);
    }
    L<<Logger::Info<<"[lookup] looking up "<<ethKey<<"/"<<ethDomain<<endl;
    string query = "/home/jgm/.go/bin/ethereal dns get --connection=" + d_connection + " --resource=" + ethResource + " --key=" + ethKey + " --domain=" + ethDomain;
    string resultsStr = this->exec(query.c_str());
    while (!resultsStr.empty() && (resultsStr[resultsStr.size() - 1] == '\r' || resultsStr[resultsStr.size() - 1] == '\n'))
      resultsStr.erase(resultsStr.size() - 1);

    if (resultsStr.length() == 0 && qdomain.toString() != ".") {
      // No results so try with a truncated domain and the key the first element
      DNSName choppedDomain(qdomain);
      choppedDomain.chopOff();
      ethDomain = choppedDomain.toString();
      ethKey = qdomain.toString();
      ethKey = ethKey.substr(0, ethKey.find("."));
      if (ethDomain.size() > 1) {
        ethDomain.erase(ethDomain.size()-1);
      }
      L<<Logger::Info<<"[lookup] looking up "<<ethKey<<"/"<<ethDomain<<endl;
      query = "/home/jgm/.go/bin/ethereal dns get --connection=" + d_connection + " --resource=" + ethResource + " --key=" + ethKey + " --domain=" + ethDomain;
      resultsStr = this->exec(query.c_str());
      while (!resultsStr.empty() && (resultsStr[resultsStr.size() - 1] == '\r' || resultsStr[resultsStr.size() - 1] == '\n'))
        resultsStr.erase(resultsStr.size() - 1);
    }

    if (resultsStr.length() > 0) {
      L<<Logger::Info<<"[lookup] Results are "<<resultsStr<<endl;
      std::vector<std::string> results;
      boost::split(results, resultsStr, boost::is_any_of("\r\n"), boost::token_compress_on);
      L<<Logger::Info<<"[lookup] number of results:  "<<results.size()<<endl;
      ZoneParserTNG zpt(results, qdomain);
      for (uint i = 0; i < results.size(); i++) {
        L<<Logger::Info<<"[lookup] Parsing result"<<endl;
        DNSResourceRecord rr;
        zpt.get(rr);
        d_records.push_back(rr);
      }
      L<<Logger::Info<<"[lookup] Results current holds "<<d_records.size()<<" records"<<endl;

//      bool finished = false;
//      while (!finished) {
//        L<<Logger::Info<<"[lookup] Parsing result"<<endl;
//        DNSResourceRecord rr;
//        finished = zpt.get(rr);
//        d_records.push_back(rr);
//      }
    }
    return;
//    string in = "example.com.    3600    IN      SOA     ns1.example.com. hostmaster.example.com. 1 900 900 1800 60\n";
//    vector<string> ins = {in};
//    ZoneParserTNG zpt(ins, DNSName("example.com"));
//    DNSResourceRecord rr;
//    bool finished = zpt.get(rr);
//    L<<Logger::Info<<"[init] rr: "<<rr.content<<endl;
//    L<<Logger::Info<<"[init] rr: "<<rr.qtype.getName()<<endl;
//    L<<Logger::Info<<"[init] rr: "<<rr.qclass<<endl;
//    L<<Logger::Info<<"[init] rr: "<<rr.ttl<<endl;
//    L<<Logger::Info<<"[init] finished?  "<<finished<<endl;

//    string query = "/home/jgm/.go/bin/ethereal dns get --wire --connection=" + d_connection + " --resource=" + ethResource + " --key=" + ethKey + " --domain=" + ethDomain;
    L<<Logger::Info<<"[lookup] Query is "<<query<<endl;
//    string resultsStr = this->exec(query.c_str());
//    while (!resultsStr.empty() && (resultsStr[resultsStr.size() - 1] == '\r' || resultsStr[resultsStr.size() - 1] == '\n'))
//      resultsStr.erase(resultsStr.size() - 1);
    string hex = this->exec(query.c_str());
    while (!hex.empty() && (hex[hex.size() - 1] == '\r' || hex[hex.size() - 1] == '\n'))
      hex.erase(hex.size() - 1);

    std::vector<char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
      std::string byteString = hex.substr(i, 2);
      char byte = (char) strtol(byteString.c_str(), NULL, 16);
      bytes.push_back(byte);
    }

    L<<Logger::Info<<"[lookup] Setting up parser "<<endl;
    MOADNSParser mdp(false, reinterpret_cast<char*>(bytes.data()));
    L<<Logger::Info<<"[lookup] Parser set up "<<endl;

//    std::size_t len = hex.length();
//    std::string result;
//    for(size_t i = 0; i < len; i += 2)
//    {
//        string byte = hex.substr(i, 2);
//        char chr = (char) (int)strtol(byte.c_str(), nullptr, 16);
//        result.push_back(chr);
//    }

//    if (resultsStr.length() > 0) {
//      L<<Logger::Info<<"[lookup] Results are "<<resultsStr<<endl;
//      std::vector<std::string> results;
//      boost::split(results, resultsStr, boost::is_any_of("\r\n"), boost::token_compress_on);
//      L<<Logger::Info<<"[lookup] number of results:  "<<results.size()<<endl;
//
//      ZoneParserTNG zpt(results, qdomain);
//      bool finished = false;
//      while (!finished) {
//        DNSResourceRecord rr;
//        finished = zpt.get(rr);
//        L<<Logger::Info<<"[lookup] finished?  "<<finished<<endl;
//        if (!finished) {
//          d_records.push_back(rr);
//        }
//        // d_types.push_back(type);
//        // d_answers.push_back(result);
//      }
//    }

    return;
  }

  bool get(DNSResourceRecord &rr) override
  {
    if (d_records.size() == 0) {
      L<<Logger::Info<<"[get] no result"<<endl;
      return false;
    }
    L<<Logger::Info<<"[get] returning result"<<endl;
    DNSResourceRecord ourRr = d_records.front();
    d_records.pop_front();
    rr.qtype = ourRr.qtype;
    rr.qclass = ourRr.qclass;
    rr.auth = 1;
    rr.qname = ourRr.qname;
    rr.ttl = ourRr.ttl;
    rr.content = ourRr.content;
    return true;
  }

  std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) throw std::runtime_error("popen() failed!");
    while (!feof(pipe.get())) {
      if (fgets(buffer.data(), 128, pipe.get()) != nullptr) {
        result += buffer.data();
      }
    }
    return result;
  }

private:
  std::list<QType> d_types;
  std::list<DNSResourceRecord> d_records;
  string d_connection;
};

/* SECOND PART */

class EnsFactory : public BackendFactory
{
public:
  EnsFactory() : BackendFactory("ens") {}
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"connection","Connection to Ethereum client","https://ropsten.orinocopay.com:8546/");
    // declare(suffix,"connection","Connection to Ethereum client","/home/ethereum/.ethereum/testnet/geth.ipc");
  }
  DNSBackend *make(const string &suffix="")
  {
    return new EnsBackend(suffix);
  }
};

/* THIRD PART */

class EnsLoader
{
public:
  EnsLoader()
  {
    BackendMakers().report(new EnsFactory);
    L << Logger::Info << "[ensbackend] This is the ENS backend version " VERSION
#ifndef REPRODUCIBLE
      << " (" __DATE__ " " __TIME__ ")"
#endif
      << " reporting" << endl;
  }  
};

static EnsLoader ensLoader;
