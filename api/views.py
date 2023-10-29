import random

from rest_framework.views import APIView
from rest_framework.response import Response

from .nagad import get_payment_information
from decouple import config


class NagadPaymentView(APIView):
    def post(self, request):
        data = request.data

        merchant_id = config('NAGAD_MERCHANT_ID')
        invoice_number = random.randint(100000, 999999)
        amount = data.get('amount')
        pg_public_key = config('NAGAD_PG_PUBLIC_KEY')
        merchant_private_key = config('NAGAD_MERCHANT_PRIVATE_KEY')
        base_url = config('NAGAD_BASE_URL')
        merchant_callback_url = config('NAGAD_MERCHANT_CALLBACK_URL')

        # Your Nagad payment logic goes here
        info = get_payment_information(
            merchant_id=merchant_id,
            invoice_number=invoice_number,
            amount=amount,
            pg_public_key=pg_public_key,
            merchant_private_key=merchant_private_key,
            base_url=base_url,
            merchant_callback_url=merchant_callback_url
        )

        return Response({'data': info}, status=200)
