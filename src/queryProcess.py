import re


class CalculatePositions:
    def __init__(self, request):
        self.orig_request = request
        self.insertionPoints = []
        self.final_positions = []
        self.positions_variables = []
        self.message = self.orig_request
        gql = self.message.find('variables')
        # print gql
        self.positions_variables = [(a.start(), a.end()) for a in list(re.finditer('variables":', self.message))]
        print self.positions_variables

    def findInsertionPoints(self):
        for item in self.positions_variables:
            length = len(self.message)
            start = item[1] + 1
            sub_string = self.message[start:length]
            size = sub_string.find('}')
            print "Size is: %d" % size
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

                print "==========Final positions for insertion==========="
                # return self.final_positions to main

            return self.final_positions
