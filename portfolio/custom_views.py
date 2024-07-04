from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.exceptions import NotFound

class CustomListCreateAPIView(generics.ListCreateAPIView):
    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        if not queryset:
            raise NotFound(detail="Data not found", code=404)

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
