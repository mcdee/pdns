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
#include <boost/algorithm/string.hpp>

/* FIRST PART */
class EnsBackend : public DNSBackend
{
public:
  EnsBackend(const string &suffix="")
  {
    setArgPrefix("ens"+suffix);
    d_connection = getArg("connection");
    d_ourname = DNSName(getArg("hostname"));
    d_ourdomain = d_ourname;
    d_ourdomain.chopOff();
    d_types = {};
    d_answers = {};

    // TODO connect to Ethereum
  }

  bool list(const DNSName &target, int id, bool include_disabled) override {
    return false; // we don't support AXFR
  }

  void lookup(const QType &type, const DNSName &qdomain, DNSPacket *p, int zoneId) override
  {
    L<<Logger::Info<<"[lookup] entered for "<<qdomain<<" "<<type.getName()<<endl;
    if (type.getCode() == QType::ANY) {
      // Loop for all of the items we care about
      this->lookup(QType(QType::SOA), qdomain, p, zoneId);
      this->lookup(QType(QType::NS), qdomain, p, zoneId);
      this->lookup(QType(QType::MX), qdomain, p, zoneId);
      this->lookup(QType(QType::A), qdomain, p, zoneId);
      this->lookup(QType(QType::CNAME), qdomain, p, zoneId);
      this->lookup(QType(QType::TXT), qdomain, p, zoneId);
      return;
    }

    // Individual record type; set up our parameters
    string ethName = qdomain.toString() + "domainmap.wealdtech.eth";
    string ethRr = type.getName();

    string query = "/home/jgm/.go/bin/ens dns get --connection=/home/jgm/.ethereum/testnet/geth.ipc --rr=" + ethRr + " " + ethName;
    L<<Logger::Info<<"[lookup] Query is "<<query<<endl;
    string hex = this->exec(query.c_str());
    while (!hex.empty() && (hex[hex.size() - 1] == '\r' || hex[hex.size() - 1] == '\n'))
      hex.erase(hex.size() - 1);

    std::size_t len = hex.length();
    std::string result;
    for(size_t i = 0; i < len; i += 2)
    {
        string byte = hex.substr(i, 2);
        char chr = (char) (int)strtol(byte.c_str(), nullptr, 16);
        result.push_back(chr);
    }

    if (result.length() > 0) {
      L<<Logger::Info<<"[lookup] Result is "<<result<<endl;
      d_types.push_back(type);
      d_answers.push_back(result);
    }

    return;
  }

  bool get(DNSResourceRecord &rr) override
  {
    L<<Logger::Info<<"[get] entered for "<<d_types.front().getName()<<endl;
    if (d_types.size() == 0) {
      L<<Logger::Info<<"[get] no results"<<endl;
      return false;
    }
    QType rrType = d_types.front();
    // Standard items for all returned resources
    rr.qtype = rrType;
    rr.qclass = QClass::IN;
    rr.auth = 1;

    // TODO
    rr.qname = d_ourdomain;
    rr.ttl = 5;

    string d_answer = d_answers.front();
    d_answers.pop_front();
    if (d_answer.find("|") == string::npos) {
      // Last record
      rr.content = d_answer;
      d_types.pop_front();
      L<<Logger::Info<<"[get] returning "<<rr.content<<" (last result)"<<endl;
    } else {
      // Take result up to next bar
      rr.content = d_answer.substr(0, d_answer.find("|"));
      d_answer = d_answer.substr(d_answer.find("|") + 1);
      d_answers.push_front(d_answer);
      L<<Logger::Info<<"[get] returning "<<rr.content<<" (more results "<<d_answers.front()<<")"<<endl;
    }
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
  std::list<string> d_answers;
  string d_connection;
  DNSName d_ourname;
  DNSName d_ourdomain;
};

/* SECOND PART */

class EnsFactory : public BackendFactory
{
public:
  EnsFactory() : BackendFactory("ens") {}
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"hostname","Hostname which is to be random","random.example.com");
    declare(suffix,"connection","Connection to Ethereum client","https://ropsten.orinocopay.com:8546/");
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
