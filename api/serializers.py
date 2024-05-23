from rest_framework import serializers
from .models import FileModel

class SpamClassifierSerializer(serializers.Serializer):
    user_message = serializers.CharField(required=True)
    user_selected_model = serializers.CharField(max_length=100, required=False)
    user_file = serializers.FileField(required=False)

    def create(self, validated_data):
        user_message = validated_data['user_message']
        user_selected_model = validated_data['user_selected_model']
        user_file = validated_data['user_file']
        if user_file:
            file_instance = FileModel(file=user_file)
            file_instance.save()
        return {'user_message': user_message, 'user_selected_model': user_selected_model, 'user_file': user_file}