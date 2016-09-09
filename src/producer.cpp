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
#include <ndn-group-encrypt/producer.hpp>
#include <ndn-group-encrypt/algo/rsa.hpp>
#include <ndn-group-encrypt/algo/aes.hpp>
#include <ndn-group-encrypt/encrypted-content.hpp>

#include <boost/filesystem.hpp>
#include <ndn-cxx/name.hpp>
#include <ndn-cxx/interest.hpp>
#include <ndn-cxx/data.hpp>
#include <ndn-cxx/link.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/encoding/buffer-stream.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <string>

namespace ndn {
namespace SampleProducer {
    
    using namespace boost::posix_time;

    static const uint8_t DATA_CONTEN[] = {
    0xcb, 0xe5, 0x6a, 0x80, 0x41, 0x24, 0x58, 0x23,
    0x84, 0x14, 0x15, 0x61, 0x80, 0xb9, 0x5e, 0xbd,
    0xce, 0x32, 0xb4, 0xbe, 0xbc, 0x91, 0x31, 0xd6,
    0x19, 0x00, 0x80, 0x8b, 0xfa, 0x00, 0x05, 0x9c
    };
    
    static const std::string READ_ACCESS_REQUEST = "/org/openmhealth/zhehao/read_access_request";
    static const std::string USER_PREFIX = "/org/openmhealth/zhehao";
    static const std::string USER_READ_PREFIX = "/org/openmhealth/zhehao/READ/fitness";
    static const std::string SCHEDULE_NAME = "schedule_name";
    static const std::string DATA_PREFIX = "/org/openmhealth/zhehao/SAMPLE";
    
    static const std::string DATABASE = "/tmp/producer-key.db";
    
    class SampleProducer : noncopyable
    {
    public:
        SampleProducer();
        ~SampleProducer();
        void onRegisterFailed(const Name& prefix, const std::string& reason);
        void onRequestInterest(const InterestFilter& filter, const Interest& interest);
        void onTimeout(const Interest& interest);
        void checkEKey(const std::vector<Data>& eKeyVector);
        void run();
    private:
        boost::asio::io_service m_ioService;
        ndn::Face m_face;
        ndn::util::Scheduler m_scheduler;
        KeyChain m_keyChain;
        ndn::gep::Producer producer;
        Data testData;
        shared_ptr<Data> testEncryptedCKey;
    };
    
    SampleProducer::SampleProducer()
    : m_face(m_ioService) // Create face with io_service object
    , m_scheduler(m_ioService)
    , producer(Name(USER_PREFIX), Name("fitness"), m_face, DATABASE, 3, Link(USER_READ_PREFIX, {{10, "/a"}}))
    {
        Name contentKeyName = producer.createContentKey(time::fromIsoString("20160321T092000"),
                                                        bind(&SampleProducer::checkEKey, this, _1));
        std::cout << "ContentKeyName: " << contentKeyName << std::endl;
        producer.produce(testData, time::fromIsoString("20160321T092000"), DATA_CONTEN, sizeof(DATA_CONTEN));
        std::cout << "Encrypteddata name: " << testData.getName() << std::endl;
    }

    SampleProducer::~SampleProducer() {
        std::remove(DATABASE.c_str());
    }

    void SampleProducer::checkEKey(const std::vector<Data>& eKeyVector) {
        std::cout << "the key size is " << eKeyVector.size() << std::endl;
        for (std::vector<Data>::const_iterator it = eKeyVector.begin() ; it != eKeyVector.end(); ++it) {
            std::cout << it->getName() << std::endl;
            testEncryptedCKey = make_shared<Data>(it->wireEncode());
            testEncryptedCKey->setName(it->getName());
        }
    }

    void SampleProducer::run()
    {
        //Name contentKeyName = producer.createContentKey(time::fromIsoString("20160321T092000"),
        //                                                bind(&SampleProducer::checkEKey, this, _1));
        //std::cout << "ContentKeyName: " << contentKeyName << std::endl;
        
        //producer.produce(testData, time::fromIsoString("20160321T092000"), DATA_CONTEN, sizeof(DATA_CONTEN));
        //std::cout << "Encrypteddata name: " << testData.getName() << std::endl;
        //accept incoming register interest
        m_face.setInterestFilter(DATA_PREFIX,
                                 bind(&SampleProducer::onRequestInterest, this, _1, _2),
                                 RegisterPrefixSuccessCallback(),
                                 bind(&SampleProducer::onRegisterFailed, this, _1, _2));

        m_ioService.run();
    }
    
    void SampleProducer::onRequestInterest(const InterestFilter& filter, const Interest& interest) {
        std::cout << "<< I: " << interest << std::endl;
        if(interest.getName().isPrefixOf(testData.getName())) {
            shared_ptr<Data> data = make_shared<Data>(testData.wireEncode());
            data->setName(testData.getName());
            m_face.put(*data);
        }
        else {
            m_face.put(*testEncryptedCKey);
        }
    }
    
    void SampleProducer::onRegisterFailed(const Name& prefix, const std::string& reason)
    {
        std::cerr << "ERROR: Failed to register prefix \""
        << prefix << "\" in local hub's daemon (" << reason << ")"
        << std::endl;
    }
    
    void SampleProducer::onTimeout(const Interest& interest){
        std::cout << "Time out I: " << interest << std::endl;
    }
    
} // namespace gep
} // namespace ndn


int main()
{
    ndn::SampleProducer::SampleProducer sampleProducer;
    try {
        sampleProducer.run();
    }
    catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
    }
    return 0;
}
