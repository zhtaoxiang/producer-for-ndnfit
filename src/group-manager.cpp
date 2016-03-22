/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2014-2015,  Regents of the University of California
 *
 * This file is part of ndn-group-encrypt (Group-based Encryption Protocol for NDN).
 * See AUTHORS.md for complete list of ndn-group-encrypt authors and contributors.
 *
 * ndn-group-encrypt is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * ndn-group-encrypt is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * ndn-group-encrypt, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @author Haitao Zhang <zhtaoxiang@gmail.com>
 */

#include <ndn-group-encrypt/group-manager.hpp>
#include <ndn-group-encrypt/algo/rsa.hpp>
#include <ndn-group-encrypt/algo/aes.hpp>
#include <ndn-group-encrypt/encrypted-content.hpp>

#include <boost/filesystem.hpp>
#include <ndn-cxx/name.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/transport/tcp-transport.hpp>
#include <string>

namespace ndn {
namespace onlinegroupmanager {
    
    using namespace boost::posix_time;
    
    static const std::string READ_ACCESS_REQUEST = "/org/openmhealth/zhehao/read_access_request";
    static const std::string URER_PREFIX = "/org/openmhealth/zhehao";
    static const std::string SCHEDULE_NAME = "schedule_name";
    
    static const std::string DATABASE = "/tmp/manager-key.db";
    
    class OnlineGroupManager : noncopyable
    {
    public:
        OnlineGroupManager();
        ~OnlineGroupManager();
        void onRegisterFailed(const Name& prefix, const std::string& reason);
        void onRequestInterest(const InterestFilter& filter, const Interest& interest);
        void onTimeout(const Interest& interest);
        void onCertData(const Interest& interest, const Data& data);
        void insertOneWeekKeyIntoRepo();
        void run();
        void putinDataCallback(const Block& wire);
    private:
        boost::asio::io_service m_ioService;
        ndn::Face m_face;
        TcpTransport tcp_connect_repo_for_put_data;
        ndn::util::Scheduler m_scheduler;
        KeyChain m_keyChain;
        ndn::gep::GroupManager manager;
    };
    
    OnlineGroupManager::OnlineGroupManager()
    : m_face(m_ioService) // Create face with io_service object
    , tcp_connect_repo_for_put_data("localhost", "7376")
    , m_scheduler(m_ioService)
    , manager(Name(URER_PREFIX), Name("/fitness"), DATABASE, 2048, 1)
    {
        ndn::gep::Schedule schedule1;
        ndn::gep::RepetitiveInterval interval1(boost::posix_time::from_iso_string("20160101T000000"),
                                               boost::posix_time::from_iso_string("20170101T000000"),
                                               8, 10, 1, ndn::gep::RepetitiveInterval::RepeatUnit::DAY);
        schedule1.addWhiteInterval(interval1);
        manager.addSchedule(SCHEDULE_NAME, schedule1);
        
        tcp_connect_repo_for_put_data.connect(m_ioService, bind(&OnlineGroupManager::putinDataCallback, this, _1));
    }
    OnlineGroupManager::~OnlineGroupManager() {
        std::remove(DATABASE.c_str());
    }
    void OnlineGroupManager::run()
    {
        //accept incoming register interest
        m_face.setInterestFilter(READ_ACCESS_REQUEST,
                                 bind(&OnlineGroupManager::onRequestInterest, this, _1, _2),
                                 RegisterPrefixSuccessCallback(),
                                 bind(&OnlineGroupManager::onRegisterFailed, this, _1, _2));

        m_ioService.run();
    }
    
    void OnlineGroupManager::onRequestInterest(const InterestFilter& filter, const Interest& interest) {
        std::cout << "<< I: " << interest << std::endl;
        Interest certInterest(interest.getName().getSubName(4));
        certInterest.setInterestLifetime(time::milliseconds(1000));
        
        m_face.expressInterest(certInterest,
                               bind(&OnlineGroupManager::onCertData, this, _1, _2),
                               bind(&OnlineGroupManager::onTimeout, this, _1));
        std::cout << "Sending " << certInterest << std::endl;
    }
    
    void OnlineGroupManager::onRegisterFailed(const Name& prefix, const std::string& reason)
    {
        std::cerr << "ERROR: Failed to register prefix \""
        << prefix << "\" in local hub's daemon (" << reason << ")"
        << std::endl;
    }
    
    void OnlineGroupManager::onCertData(const Interest& interest, const Data& data) {
        std::cout << "<< D: " << data << std::endl;
        try {
            manager.addMember(SCHEDULE_NAME, data);
        } catch (std::runtime_error e) {
            std::cout << e.what() << std::endl;
        }
        Name requestSuccessName = Name(READ_ACCESS_REQUEST).append(interest.getName());
        shared_ptr<Data> requestSuccessData = make_shared<Data>();
        requestSuccessData->setName(requestSuccessName);
        requestSuccessData->setFreshnessPeriod(time::seconds(10));
        m_keyChain.sign(*requestSuccessData);
        std::cout << ">> D: " << *requestSuccessData << std::endl;
        m_face.put(*requestSuccessData);
        insertOneWeekKeyIntoRepo();
    }
    
    void OnlineGroupManager::onTimeout(const Interest& interest){
        std::cout << "Time out I: " << interest << std::endl;
    }
    
    void OnlineGroupManager::insertOneWeekKeyIntoRepo() {
        ndn::gep::TimeStamp tsNow = from_iso_string("20160320T000000");
        std::list<Data> keys;
        for (int i = 0; i < 7 * 24; i ++) {
            keys = manager.getGroupKey(tsNow + hours(i));
            for (std::list<Data>::iterator it=keys.begin(); it != keys.end(); ++it) {
                std::cout << "KEY: " << it->getName() << std::endl;
                tcp_connect_repo_for_put_data.send((*it).wireEncode());
            }
        }
    }
    
    void OnlineGroupManager::putinDataCallback(const Block& wire) {
        if (wire.type() == ndn::tlv::Data) {
            Data data(wire);
            // if the data packet is not there in the repo, send interest to get data
            if(data.getContent().value_size() == 0) {
                std::cout << "Put data into repo failed" << std::endl;
            }
        }
        else {
            std::cout << "Put data into repo failed" << std::endl;
        }
        return;
    }
    
} // namespace gep
} // namespace ndn


int main()
{
    ndn::onlinegroupmanager::OnlineGroupManager onlineGroupManager;
    try {
        onlineGroupManager.run();
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
    return 0;
}