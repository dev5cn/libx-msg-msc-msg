/*
  Copyright 2019 www.dev5.cn, Inc. dev5@qq.com
 
  This file is part of X-MSG-IM.
 
  X-MSG-IM is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  X-MSG-IM is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
 
  You should have received a copy of the GNU Affero General Public License
  along with X-MSG-IM.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "XmsgMscMsg.h"
#include "mgr/XmsgImMgrNeNetLoad.h"
#include "mgr/XmsgImMgrNeXscServerQuery.h"
#include "mgr/XmsgImMgrNeXscWorkerCount.h"
#include "msg/XmsgMscSubNeGroupStatus.h"
#include "msg/XmsgNeAuth.h"

XmsgMscMsg::XmsgMscMsg()
{

}

void XmsgMscMsg::init(shared_ptr<XmsgImN2HMsgMgr> pubMsgMgr, shared_ptr<XmsgImN2HMsgMgr> priMsgMgr)
{
	X_MSG_N2H_PRPC_BEFOR_AUTH(pubMsgMgr, XmsgNeAuthReq, XmsgNeAuthRsp, XmsgNeAuth::handle4msc)
	pubMsgMgr->setItcp([](XscWorker* wk, XscChannel* channel , shared_ptr<XscProtoPdu> pdu)
	{
		if(pdu->transm.header == NULL || pdu->transm.header->route == NULL) 
		{
			return XscMsgItcpRetType::DISABLE;
		}
		return XmsgMscMsg::route(channel, pdu);
	});
	X_MSG_N2H_PRPC_BEFOR_AUTH(priMsgMgr, XmsgNeAuthReq, XmsgNeAuthRsp, XmsgNeAuth::handle4ne)
	priMsgMgr->setItcp([](XscWorker* wk, XscChannel* channel , shared_ptr<XscProtoPdu> pdu)
	{
		if(pdu->transm.header == NULL || pdu->transm.header->route == NULL) 
		{
			return XscMsgItcpRetType::DISABLE;
		}
		return XmsgMscMsg::route(channel, pdu);
	});
	X_MSG_N2H_PRPC_AFTER_AUTH(priMsgMgr, XmsgImMgrNeNetLoadReq, XmsgImMgrNeNetLoadRsp, XmsgImMgrNeNetLoad::handle)
	X_MSG_N2H_PRPC_AFTER_AUTH(priMsgMgr, XmsgImMgrNeXscServerQueryReq, XmsgImMgrNeXscServerQueryRsp, XmsgImMgrNeXscServerQuery::handle)
	X_MSG_N2H_PRPC_AFTER_AUTH(priMsgMgr, XmsgImMgrNeXscWorkerCountReq, XmsgImMgrNeXscWorkerCountRsp, XmsgImMgrNeXscWorkerCount::handle)
	X_MSG_N2H_PRPC_AFTER_AUTH(priMsgMgr, XmsgMscSubNeGroupStatusReq, XmsgMscSubNeGroupStatusRsp, XmsgMscSubNeGroupStatus::handle)
}

XscMsgItcpRetType XmsgMscMsg::route(XscChannel* channel, shared_ptr<XscProtoPdu> pdu)
{
	XmsgMscMsg::tracing(channel, pdu);
	SptrCgt dest = ChannelGlobalTitle::parse(pdu->transm.header->route->dne); 
	if (dest == nullptr)
	{
		LOG_DEBUG("destination channel global title format error, sne: %s, dne: %s", pdu->transm.header->route->sne.c_str(), pdu->transm.header->route->dne.c_str())
		return XscMsgItcpRetType::FORBIDDEN;
	}
	if (XmsgMscMgr::instance()->isRoute2superior(dest))
	{
		XmsgMscMgr::route2superior(channel, pdu, dest);
		return XscMsgItcpRetType::SUCCESS;
	}
	if (dest->domain != XmsgMscCfg::instance()->cgt->domain) 
	{
		XmsgMscMgr::route2subordinate(channel, pdu, dest);
		return XscMsgItcpRetType::SUCCESS;
	}
	if (dest->hlr == XmsgMscCfg::instance()->cgt->hlr) 
	{
		if (dest->uid == XmsgMscCfg::instance()->cgt->uid) 
			return XscMsgItcpRetType::DISABLE;
		LOG_FAULT("unsupported route message to partner in same group, self: %s, dest: %s", XmsgMscCfg::instance()->cgt->toString().c_str(), dest->toString().c_str())
		return XscMsgItcpRetType::FORBIDDEN; 
	}
	XmsgMscMgr::route2service(channel, pdu, dest);
	return XscMsgItcpRetType::SUCCESS;
}

void XmsgMscMsg::tracing(XscChannel* channel, shared_ptr<XscProtoPdu> pdu)
{
	if (pdu->transm.header == nullptr || pdu->transm.header->trace == nullptr) 
		return;
	::memcpy(pdu->transm.header->trace->pid, pdu->transm.header->trace->sid, sizeof(pdu->transm.header->trace->sid)); 
	XscMisc::uuid(pdu->transm.header->trace->sid);
	pdu->transm.header->trace->sne = XmsgMscCfg::instance()->cfgPb->cgt(); 
	auto usr = channel->usr.lock();
	if (usr == nullptr) 
	{
		LOG_ERROR("why this channel`s usr information is null, channel: %s", channel->toString().c_str())
	}
	pdu->transm.header->trace->dne = usr == nullptr ? channel->peer : usr->uid;
	pdu->transm.header->trace->gts = DateMisc::nowGmt0();
	XmsgDst::instance()->write(XmsgMscCfg::instance()->cgt, pdu); 
}

XmsgMscMsg::~XmsgMscMsg()
{

}

