import platform

if platform.system() != "Java":
    print("Load this file inside jython, if you need the stand-alone tool run: inql")
    exit(-1)

import re

from burp import IScannerInsertionPointProvider, IScannerInsertionPoint, IParameter

from inql.utils import string_join


class BurpInsertionPointProvider(IScannerInsertionPointProvider):
    """
    Insertion Points provider.

    """
    def __init__(self, helpers):
        self._helpers = helpers

    def getInsertionPoints(self, baseRequestResponse):
        """
        Define function to fetch Insertion Points.

        :param baseRequestResponse:
        :return: return the insertion points
        """
        # Get the parameter for insertion
        dataParameter = self._helpers.getRequestParameter(baseRequestResponse.getRequest(), "data")
        if dataParameter is None:
            return None
        else:
            # One insertion point at a time
            return [_InsertionPoint(self._helpers, baseRequestResponse.getRequest(), dataParameter.getValue())]


class _InsertionPoint(IScannerInsertionPoint):
    """
    InsertiionPoint implementer
    """
    def __init__(self, helpers, baseRequest, dataParameter):
        self._helpers = helpers
        self._baseRequest = baseRequest
        self.final_positions = []
        dataParameter = helpers.bytesToString(dataParameter)
        # Implement Query Process to get Insertion Points
        request = query_process(dataParameter)  # TODO: isn't this thing completely bogus?
        request.findInsertionPoints()
        self.final_positions = request.findFinalPositions()

        # Loop through to Create prefix and suffix for insertion Points
        for ins_point in self.final_positions:
            start = ins_point[0]
            end = ins_point[1]
            self._insertionPointPrefix = dataParameter[:start]
            if (end == -1):
                end = dataParameter.length()
            self._baseValue = dataParameter[start:end]
            self._insertionPointSuffix = dataParameter[end:]

        return

    def getInsertionPointName(self):
        """
        :return: insertion point name
        """
        return self._baseValue

    def buildRequest(self, payload):
        """
        Build a request based on the input.

        :param payload: build request based on input
        :return: a new request with updated parameters.
        """
        input(string_join(self._insertionPointPrefix, self._helpers.bytesToString(payload), self._insertionPointSuffix))
        return self._helpers.updateParameter(self._baseRequest, self._helpers.buildParameter("data"), input,
                                             IParameter.PARAM_BODY)

    def getPayloadOffsets(self, payload):
        """
        Get Payload Offsets. Unimplemented.

        :param payload: ignored.
        :return: None
        """
        return None

    def getInsertionPointType(self):
        """
        :return: IScannerInsertionPoint.INS_EXTENSION_PROVIDED
        """
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED


class _CalculatePositions:
    """
    XXX: Unused. it should provide query_process functionalities
    """
    def __init__(self, request):
        self.orig_request = request
        self.insertionPoints = []
        self.final_positions = []
        self.positions_variables = []
        self.message = self.orig_request
        gql = self.message.find('variables')
        # print gql
        self.positions_variables = [(a.start(), a.end()) for a in list(re.finditer('variables":', self.message))]
        print(self.positions_variables)

    def findInsertionPoints(self):
        for item in self.positions_variables:
            length = len(self.message)
            start = item[1] + 1
            sub_string = self.message[start:length]
            size = sub_string.find('}')
            print("Size is: %d" % size)
            end = start + size
            sub_string2 = self.message[start:end]
            self.insertionPoints.append((start, end))

    def findFinalPositions(self):
        for point in self.insertionPoints:
            positions2 = []
            positions1 = []
            if point[0] == point[1]:
                # self.final_positions.append(point)
                continue
            else:
                point_start = point[0]
                point_end = point[1] + 1
                sub_string3 = self.message[point_start:point_end]
                # print "sub_string3 is %s: " % sub_string3
                positions1 = [(b.end()) for b in list(re.finditer(':"', sub_string3))]
                positions2 = [(c.end()) for c in list(re.finditer('",', sub_string3))]
                endpos = sub_string3.find('"}')
                positions2.append(endpos)
                positions = zip(positions1, positions2)
                for ins in positions:
                    # print sub_string3[ins[0]:ins[1]]
                    self.final_positions.append((point_start + ins[0], point_start + ins[1]))

                print("==========Final positions for insertion===========")
                # return self.final_positions to main

            return self.final_positions